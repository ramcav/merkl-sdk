/**
 * @merkl-ai/verify — the JavaScript half of Merkl's verification.
 *
 * One normative spec, one vector set, two implementations (plan D7). Everything
 * here has a counterpart in `merkl.core.verify`, computes the same bytes, reports
 * the same check names and produces the same verdicts over the same fixtures in
 * `merkl/core/vectors/`. A divergence between the two is a bug in one of them; it
 * is never "a difference between the Python and the JavaScript".
 *
 * No dependencies. Web Crypto only, so the same file runs in a browser opening
 * verify.html offline and under `node --test` in CI. Nothing here reads a clock:
 * `now` is an argument everywhere, because a reader's clock is not evidence and a
 * verifier that consults one cannot be checked against a fixture.
 *
 * Layout, in the order a reader needs it:
 *
 *   1. bytes, hex, base64            8. approvals (WebAuthn, Ed25519)
 *   2. canonical JSON                9. CBOR (the attestation profile)
 *   3. checks and results           10. DER / X.509 (four fields, exactly)
 *   4. Merkle folds                 11. attestation documents
 *   5. session log encodings        12. settlement proofs
 *   6. receipt tree                 13. the receipt verdict
 *   7. signatures                   14. the bundle
 */

// ─── 1. bytes, hex, base64 ──────────────────────────────────────────────────

const TE = new TextEncoder();

export function utf8(s) {
  return TE.encode(String(s));
}

export function toHex(bytes) {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

export function fromHex(hex) {
  const s = String(hex ?? '');
  if (s.length % 2 !== 0 || /[^0-9a-fA-F]/.test(s)) return null;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < s.length; i += 2) out[i >> 1] = parseInt(s.slice(i, i + 2), 16);
  return out;
}

/** Hex that must parse. Throws, for callers that already checked the shape. */
export function hexBytes(hex, what = 'value') {
  const raw = fromHex(hex);
  if (raw === null) throw new Error(`${what} is not hex`);
  return raw;
}

export function concatBytes(arrays) {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

export function bytesEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function fromBase64(value) {
  const clean = String(value ?? '').replace(/\s+/g, '');
  try {
    if (typeof atob === 'function') {
      const bin = atob(clean);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    }
    return new Uint8Array(Buffer.from(clean, 'base64'));
  } catch {
    return null;
  }
}

export function fromBase64Url(value) {
  const s = String(value ?? '')
    .replace(/-/g, '+')
    .replace(/_/g, '/');
  return fromBase64(s + '='.repeat((4 - (s.length % 4)) % 4));
}

/** Big-endian unsigned integer of `size` bytes. */
export function uintBE(value, size) {
  const out = new Uint8Array(size);
  let v = BigInt(value);
  for (let i = size - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

export async function sha256(data) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

export async function sha512Half(data) {
  const full = new Uint8Array(await crypto.subtle.digest('SHA-512', data));
  return full.slice(0, 32);
}

const NUL_BYTE = new Uint8Array([0]);
const NUL_CHAR = String.fromCharCode(0);

// ─── 2. canonical JSON ──────────────────────────────────────────────────────

/**
 * A byte-exact port of `merkl.shared.hashing.canonical_bytes`.
 *
 * Python side: `json.dumps(v, sort_keys=True, default=str, separators=(",", ":"))`
 * with `ensure_ascii`. Every character outside 0x20-0x7E becomes a lowercase
 * `\uXXXX` escape and keys sort. This is *the* place where two implementations
 * silently disagree, so it is reproduced escape by escape rather than delegated
 * to `JSON.stringify`.
 *
 * Known edge: keys are sorted by UTF-16 code unit here and by code point in
 * Python, which differ only for astral-plane keys. Receipt content is a
 * restricted subset that has never held one; if that changes, this is the line.
 */
const JSON_SHORT = { 8: '\\b', 9: '\\t', 10: '\\n', 12: '\\f', 13: '\\r', 34: '\\"', 92: '\\\\' };

export function pythonJsonString(s) {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (JSON_SHORT[c]) out += JSON_SHORT[c];
    else if (c < 0x20 || c > 0x7e) out += '\\u' + c.toString(16).padStart(4, '0');
    else out += s[i];
  }
  return out + '"';
}

export function canonicalJson(value) {
  if (value === null || value === undefined) return 'null';
  const t = typeof value;
  if (t === 'boolean') return value ? 'true' : 'false';
  if (t === 'number') return JSON.stringify(value);
  if (t === 'string') return pythonJsonString(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  return (
    '{' +
    Object.keys(value)
      .sort()
      .map((k) => pythonJsonString(k) + ':' + canonicalJson(value[k]))
      .join(',') +
    '}'
  );
}

export async function canonicalHashHex(value) {
  return toHex(await sha256(utf8(canonicalJson(value))));
}

// ─── 3. checks and results ──────────────────────────────────────────────────

export const PASS = 'pass';
export const FAIL = 'fail';
export const NOT_IMPLEMENTED = 'not_implemented';

export function check(name, status, detail = '') {
  return { name, status, detail };
}

/** A check that ran: pass or fail, never anything in between. */
export function outcome(name, passed, detail = '') {
  return check(name, passed ? PASS : FAIL, detail);
}

/**
 * A check whose inputs are not there. Not a pass — the absence of data is never
 * reported as agreement.
 */
export function noData(name, detail) {
  return check(name, NOT_IMPLEMENTED, detail);
}

export function result(checks) {
  const list = checks.slice();
  return {
    checks: list,
    get ok() {
      return !list.some((c) => c.status === FAIL);
    },
    get complete() {
      return !list.some((c) => c.status === NOT_IMPLEMENTED);
    },
    get failures() {
      return list.filter((c) => c.status === FAIL);
    },
    get deferred() {
      return list.filter((c) => c.status === NOT_IMPLEMENTED);
    },
    get(name) {
      return list.find((c) => c.name === name) ?? null;
    },
  };
}

// ─── 4. Merkle folds ────────────────────────────────────────────────────────

/** `SHA-256(left || right)` over raw 32-byte digests. The only interior rule. */
export async function hashPair(left, right) {
  return sha256(concatBytes([left, right]));
}

/** Fold a leaf up a path of siblings and directions. Null when malformed. */
export async function deriveRoot(leafHex, siblings, directions) {
  let current = fromHex(leafHex);
  if (current === null || current.length !== 32) return null;
  if (!Array.isArray(siblings) || !Array.isArray(directions)) return null;
  if (siblings.length !== directions.length) return null;
  for (let i = 0; i < siblings.length; i++) {
    const sibling = fromHex(siblings[i]);
    if (sibling === null || sibling.length !== 32) return null;
    if (directions[i] === 'left') current = await hashPair(sibling, current);
    else if (directions[i] === 'right') current = await hashPair(current, sibling);
    else return null;
  }
  return toHex(current);
}

/** Merkl's tree: pad to the next power of two by repeating the last leaf. */
export async function merkleRoot(leafHexes) {
  if (!leafHexes.length) return null;
  let level = leafHexes.map((h) => fromHex(h));
  if (level.some((l) => l === null || l.length !== 32)) return null;
  let size = 1;
  while (size < level.length) size *= 2;
  while (level.length < size) level.push(level[level.length - 1]);
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(await hashPair(level[i], level[i + 1]));
    level = next;
  }
  return toHex(level[0]);
}

// ─── 5. session log encodings (merkl-api/docs/SPEC.md, frozen) ──────────────

export const ACTION_LEAF_TAG = utf8('merkl-leaf-v1');
export const BINDING_TAG = utf8('merkl-binding-v1');
export const ENTRY_TAG = utf8('merkl-entry-v1');

/**
 * `merkl-leaf-v1`. Two fields decide whether a non-Python verifier agrees:
 * `drift_score` is Python's `str()` of the float — take `drift_score_str` when
 * the bundle carries it, because JSON parsing has already destroyed `"0.0"` —
 * and `timestamp` is the exact string that was transmitted, never re-rendered
 * from a Date.
 */
export async function actionLeafHash(action) {
  const drift =
    action.drift_score_str !== undefined && action.drift_score_str !== null
      ? String(action.drift_score_str)
      : String(action.drift_score ?? 0);
  const fields = [
    String(action.action_id ?? ''),
    String(action.session_id ?? ''),
    String(action.action_type ?? ''),
    String(action.tool_name ?? ''),
    String(action.input_hash ?? ''),
    String(action.output_hash ?? ''),
    String(action.timestamp ?? ''),
    drift,
    String(action.guardrail_result ?? ''),
    String(action.display_name ?? ''),
    (action.depends_on ?? []).map(String).slice().sort().join(','),
    String(action.status ?? 'success'),
    String(action.category ?? ''),
  ];
  const body = concatBytes([ACTION_LEAF_TAG, NUL_BYTE, utf8(fields.join(NUL_CHAR))]);
  return toHex(await sha256(body));
}

/** `SHA-256("merkl-binding-v1" || NUL || parent_id || parent_root || reason)`. */
export async function bindingLeafHash(parentSessionId, parentRoot, reason) {
  const root = fromHex(parentRoot);
  if (root === null) return null;
  const body = concatBytes([BINDING_TAG, NUL_BYTE, utf8(parentSessionId), root, utf8(reason)]);
  return toHex(await sha256(body));
}

function uuidBytes(value) {
  return fromHex(String(value ?? '').replace(/-/g, ''));
}

/** The audit-log entry hash. Counts are eight-byte big-endian; hashes are raw. */
export async function auditEntryHash(entry) {
  const workspace = uuidBytes(entry.workspace_id);
  const root = fromHex(entry.session_root);
  const prev = fromHex(entry.prev_log_hash);
  if (!workspace || workspace.length !== 16 || !root || !prev) return null;
  const body = concatBytes([
    ENTRY_TAG,
    NUL_BYTE,
    workspace,
    utf8(entry.session_id),
    root,
    uintBE(entry.leaf_count, 8),
    utf8(entry.sealed_at_iso),
    uintBE(entry.sequence, 8),
    prev,
  ]);
  return toHex(await sha256(body));
}

/** RFC 6962 leaf: `SHA-256(0x00 || entry_hash)`. */
export async function rfc6962Leaf(entryHash) {
  const raw = fromHex(entryHash);
  if (raw === null) return null;
  return sha256(concatBytes([new Uint8Array([0]), raw]));
}

async function rfc6962Node(left, right) {
  return sha256(concatBytes([new Uint8Array([1]), left, right]));
}

/** RFC 9162 section 2.1.3.2 inclusion verification. Returns `{ok, detail}`. */
export async function verifyLogInclusion(inclusion) {
  const leaf = await rfc6962Leaf(inclusion?.entry_hash);
  if (leaf === null) return { ok: false, detail: 'the entry hash is not hex' };
  if (toHex(leaf) !== String(inclusion.leaf_hash)) {
    return { ok: false, detail: 'the log leaf is not SHA-256(0x00 || entry_hash)' };
  }
  let fn = Number(inclusion.sequence);
  let sn = Number(inclusion.tree_size) - 1;
  const path = Array.isArray(inclusion.path) ? inclusion.path : null;
  if (!Number.isInteger(fn) || !Number.isInteger(sn) || path === null) {
    return { ok: false, detail: 'the inclusion proof is malformed' };
  }
  if (fn < 0 || fn > sn) {
    return { ok: false, detail: `sequence ${fn} is outside a tree of size ${sn + 1}` };
  }
  let node = leaf;
  for (const sibling of path) {
    if (sn === 0) return { ok: false, detail: 'the path is longer than the tree is deep' };
    const raw = fromHex(sibling);
    if (raw === null) return { ok: false, detail: 'a path element is not hex' };
    if (fn % 2 === 1 || fn === sn) {
      node = await rfc6962Node(raw, node);
      while (fn % 2 === 0 && fn !== 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      node = await rfc6962Node(node, raw);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  if (sn !== 0) return { ok: false, detail: 'the path ended before the root' };
  const root = String(inclusion.root_hash ?? '');
  return {
    ok: toHex(node) === root,
    detail: `the entry folds to ${toHex(node)}, the log root is ${root}`,
  };
}

/** The signed note must claim the tree size and root the bundle states. */
export function checkpointBodyMatches(checkpoint) {
  const body = checkpoint?.body;
  if (typeof body !== 'string') return { ok: false, detail: 'the checkpoint carries no body' };
  const lines = body.split('\n');
  if (lines.length < 3) return { ok: false, detail: 'the signed note has fewer than three lines' };
  if (lines[0] !== String(checkpoint.origin ?? '')) {
    return { ok: false, detail: `the body's origin is ${JSON.stringify(lines[0])}` };
  }
  if (lines[1] !== String(checkpoint.tree_size ?? '')) {
    return { ok: false, detail: `the body's tree size is ${JSON.stringify(lines[1])}` };
  }
  const root = fromBase64(lines[2]);
  if (root === null) return { ok: false, detail: "the body's root is not base64" };
  const claimed = String(checkpoint.root_hash ?? '');
  return {
    ok: toHex(root) === claimed,
    detail: `the body claims root ${toHex(root)}, the bundle states ${claimed}`,
  };
}

// ─── 6. receipt tree ────────────────────────────────────────────────────────

export const RECEIPT_LEAF_TAG = utf8('merkl-receipt-leaf-v1');
export const RECEIPT_VERSION = 'merkl-receipt-v1';

export const LEAF_NAMES = [
  'instruction',
  'intent',
  'policy_decision',
  'signer_attestation',
  'settlement',
  'result',
  'reasoning',
];

export const REQUIRED_LEAVES = ['instruction', 'intent', 'policy_decision'];

/**
 * `SHA-256("merkl-receipt-leaf-v1" || NUL || leaf_name || NUL || canonical(content))`.
 * Absent content is the literal `null`, so a receipt with no attestation still
 * commits to *having* none.
 */
export async function receiptLeafHash(name, content) {
  const body = utf8(canonicalJson(content === undefined ? null : content));
  return toHex(await sha256(concatBytes([RECEIPT_LEAF_TAG, NUL_BYTE, utf8(name), NUL_BYTE, body])));
}

async function foldFour(hexes) {
  const a = await hashPair(hexBytes(hexes[0]), hexBytes(hexes[1]));
  const b = await hashPair(hexBytes(hexes[2]), hexBytes(hexes[3]));
  return toHex(await hashPair(a, b));
}

export async function buildLeft(leafHashes) {
  return foldFour(leafHashes.slice(0, 4));
}

export async function buildRight(leafHashes) {
  return foldFour(leafHashes.slice(4, 8));
}

export async function buildRoot(left, right) {
  return toHex(await hashPair(hexBytes(left), hexBytes(right)));
}

/**
 * `LEFT_pre` — the digest approvers sign (spec section 3.2).
 *
 * LEFT over leaves 0-3 with leaf 2's `escalation` omitted and `outcome` forced
 * to `escalate`. Those two edits are exactly what resolving an escalation
 * changes, which is what lets a reader holding only the finished receipt check
 * that the approvers signed *this* payment and not another one.
 */
export async function escalationChallenge(contents) {
  if (!Array.isArray(contents) || contents.length < 4) return null;
  const decision = contents[2];
  if (decision === null || typeof decision !== 'object' || Array.isArray(decision)) return null;
  const pre = {};
  for (const k of Object.keys(decision)) if (k !== 'escalation') pre[k] = decision[k];
  pre.outcome = 'escalate';
  const head = [contents[0], contents[1], pre, contents[3]];
  const hashes = [];
  for (let i = 0; i < 4; i++) hashes.push(await receiptLeafHash(LEAF_NAMES[i], head[i]));
  return foldFour(hashes);
}

// ─── 7. signatures ──────────────────────────────────────────────────────────

/**
 * Ed25519 over Web Crypto. Returns `true`, `false`, or `null` when this runtime
 * has no Ed25519 — which some browsers still do not. `null` becomes a named
 * `not_implemented` check upstream, never a quiet pass.
 */
export async function ed25519Verify(publicKeyHex, signatureHex, message) {
  const key = fromHex(publicKeyHex);
  const sig = fromHex(signatureHex);
  if (!key || key.length !== 32 || !sig || sig.length !== 64) return false;
  try {
    const imported = await crypto.subtle.importKey('raw', key, { name: 'Ed25519' }, false, [
      'verify',
    ]);
    return await crypto.subtle.verify({ name: 'Ed25519' }, imported, sig, message);
  } catch (e) {
    if (e && (e.name === 'NotSupportedError' || /unsupported|unrecognized/i.test(String(e)))) {
      return null;
    }
    return false;
  }
}

/** DER `SEQUENCE {r INTEGER, s INTEGER}` to the fixed-width `r || s` Web Crypto wants. */
export function derSignatureToRaw(der, size) {
  if (!der || der.length < 8 || der[0] !== 0x30) return null;
  let i = 1;
  let len = der[i++];
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n < 1 || n > 2) return null;
    len = 0;
    for (let k = 0; k < n; k++) len = (len << 8) | der[i++];
  }
  const out = new Uint8Array(size * 2);
  for (const half of [0, 1]) {
    if (der[i++] !== 0x02) return null;
    const ilen = der[i++];
    if (ilen & 0x80) return null;
    let value = der.subarray(i, i + ilen);
    i += ilen;
    while (value.length && value[0] === 0x00) value = value.subarray(1);
    if (value.length > size) return null;
    out.set(value, half * size + (size - value.length));
  }
  return out;
}

async function ecdsaVerify(spki, curve, hash, signatureRaw, message) {
  const key = await crypto.subtle.importKey(
    'spki',
    spki,
    { name: 'ECDSA', namedCurve: curve },
    false,
    ['verify'],
  );
  return crypto.subtle.verify({ name: 'ECDSA', hash }, key, signatureRaw, message);
}

const P256_SPKI_PREFIX = new Uint8Array([
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
  0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
]);

/** ECDSA P-256 / SHA-256 over an uncompressed SEC1 point and a DER signature. */
export async function p256Verify(publicKeyHex, derSignatureHex, message) {
  const point = fromHex(publicKeyHex);
  const der = fromHex(derSignatureHex);
  if (!point || point.length !== 65 || point[0] !== 0x04 || !der) return false;
  const raw = derSignatureToRaw(der, 32);
  if (raw === null) return false;
  try {
    return await ecdsaVerify(
      concatBytes([P256_SPKI_PREFIX, point]),
      'P-256',
      'SHA-256',
      raw,
      message,
    );
  } catch {
    return false;
  }
}

// secp256k1: Web Crypto has no support for this curve (it is not one of the
// NIST curves browsers implement), so XRPL validator and manifest signatures
// need a hand-written, constant-time-not-required verifier. Correctness here
// means agreeing with Python's `cryptography` over the same real testnet
// signatures — see `merkl/core/vectors/xrpl/cases.json` — and against the
// standard secp256k1 test vectors in `tests/js/xrpl.test.mjs`.
const SECP256K1_P = 2n ** 256n - 2n ** 32n - 977n;
const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const SECP256K1_G = [
  0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
];

function mod(a, m) {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

function modPow(base, exp, m) {
  let result = 1n;
  base = mod(base, m);
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % m;
    exp >>= 1n;
    base = (base * base) % m;
  }
  return result;
}

/** Extended Euclid. ``m`` is always prime here (the field or the curve order). */
function modInverse(a, m) {
  let [oldR, r] = [mod(a, m), m];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  return mod(oldS, m);
}

function ecDouble(point) {
  if (point === null) return null;
  const [x, y] = point;
  if (y === 0n) return null;
  const lambda = mod(3n * x * x * modInverse(2n * y, SECP256K1_P), SECP256K1_P);
  const x3 = mod(lambda * lambda - 2n * x, SECP256K1_P);
  return [x3, mod(lambda * (x - x3) - y, SECP256K1_P)];
}

function ecAdd(p1, p2) {
  if (p1 === null) return p2;
  if (p2 === null) return p1;
  const [x1, y1] = p1;
  const [x2, y2] = p2;
  if (x1 === x2) {
    if (mod(y1 + y2, SECP256K1_P) === 0n) return null;
    return ecDouble(p1);
  }
  const lambda = mod((y2 - y1) * modInverse(x2 - x1, SECP256K1_P), SECP256K1_P);
  const x3 = mod(lambda * lambda - x1 - x2, SECP256K1_P);
  return [x3, mod(lambda * (x1 - x3) - y1, SECP256K1_P)];
}

/** Double-and-add. Not constant-time — this is a verifier, not a signer. */
function ecScalarMult(k, point) {
  let result = null;
  let addend = point;
  let n = k;
  while (n > 0n) {
    if (n & 1n) result = ecAdd(result, addend);
    addend = ecDouble(addend);
    n >>= 1n;
  }
  return result;
}

function bytesToBigInt(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n;
}

/** The compressed SEC1 point (0x02/0x03 ‖ X) XRPL's node keys use, decoded and on-curve. */
function secp256k1DecompressPoint(compressed) {
  if (!compressed || compressed.length !== 33) return null;
  const prefix = compressed[0];
  if (prefix !== 2 && prefix !== 3) return null;
  const x = bytesToBigInt(compressed.subarray(1));
  const rhs = mod(((x * x) % SECP256K1_P) * x + 7n, SECP256K1_P);
  let y = modPow(rhs, (SECP256K1_P + 1n) / 4n, SECP256K1_P);
  if (mod(y * y, SECP256K1_P) !== rhs) return null;
  if ((y % 2n === 0n) !== (prefix === 2)) y = SECP256K1_P - y;
  return [x, y];
}

/** DER ``SEQUENCE { r INTEGER, s INTEGER }`` as two bigints. ``null`` if malformed. */
function parseDerToScalars(der) {
  if (!der || der.length < 8 || der[0] !== 0x30) return null;
  let i = 1;
  let len = der[i++];
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n < 1 || n > 2 || i + n > der.length) return null;
    len = 0;
    for (let k = 0; k < n; k++) len = (len << 8) | der[i++];
  }
  if (i + len !== der.length) return null;
  const values = [];
  for (let half = 0; half < 2; half++) {
    if (der[i++] !== 0x02) return null;
    const ilen = der[i++];
    if (ilen === 0 || i + ilen > der.length) return null;
    values.push(bytesToBigInt(der.subarray(i, i + ilen)));
    i += ilen;
  }
  return i === der.length ? values : null;
}

/**
 * ECDSA-secp256k1 verify over an already-hashed 32-byte digest.
 *
 * XRPL hashes every object with SHA-512Half before signing, never SHA-256, so
 * this never hashes anything itself — the caller passes the digest.
 * ``publicKeyHex`` is the 33-byte compressed point, ``signatureHex`` is DER.
 */
export function secp256k1VerifyDigest(publicKeyHex, signatureHex, digest) {
  const point = secp256k1DecompressPoint(fromHex(publicKeyHex));
  if (!point) return false;
  const scalars = parseDerToScalars(fromHex(signatureHex));
  if (!scalars) return false;
  const [r, s] = scalars;
  if (r <= 0n || r >= SECP256K1_N || s <= 0n || s >= SECP256K1_N) return false;
  const e = mod(bytesToBigInt(digest), SECP256K1_N);
  const w = modInverse(s, SECP256K1_N);
  const u1 = mod(e * w, SECP256K1_N);
  const u2 = mod(r * w, SECP256K1_N);
  const sum = ecAdd(ecScalarMult(u1, SECP256K1_G), ecScalarMult(u2, point));
  return sum !== null && mod(sum[0], SECP256K1_N) === r;
}

// ─── 8. approvals (plan D11, spec section 3.3) ─────────────────────────────

const WEBAUTHN_GET = 'webauthn.get';
const FLAG_USER_PRESENT = 0x01;
const FLAG_USER_VERIFIED = 0x04;

function effectiveRpId(credential) {
  if (credential.rp_id) return credential.rp_id;
  for (const origin of credential.origins ?? []) {
    const host = String(origin).split('://').pop().split('/')[0].split(':')[0];
    if (host) return host;
  }
  return null;
}

/**
 * One assertion against one credential and one challenge.
 *
 * Never throws for a bad signature or a mismatched origin: those are findings,
 * reported next to the approvals that did count. Returns
 * `{approver_id, valid, detail}`.
 */
export async function verifyAssertion(assertion, challengeBytes, credential) {
  const no = (detail) => ({ approver_id: assertion?.approver_id ?? '', valid: false, detail });
  if (!assertion || !credential) return no('assertion or credential missing');
  if (assertion.approver_id !== credential.id) {
    return no(
      `assertion names ${JSON.stringify(assertion.approver_id)}, credential is ` +
        `${JSON.stringify(credential.id)}`,
    );
  }
  if (assertion.credential_type !== credential.credential_type) {
    return no(
      `policy registers ${credential.id} as ${credential.credential_type}, ` +
        `assertion is ${assertion.credential_type}`,
    );
  }
  if (!challengeBytes || challengeBytes.length !== 32) return no('challenge must be 32 bytes');

  if (assertion.credential_type === 'ed25519') {
    const ok = await ed25519Verify(credential.public_key, assertion.signature, challengeBytes);
    if (ok === null) {
      return {
        approver_id: assertion.approver_id,
        valid: false,
        detail: 'this runtime has no Ed25519 in Web Crypto, so the assertion is unchecked',
        unsupported: true,
      };
    }
    return {
      approver_id: assertion.approver_id,
      valid: ok,
      detail: ok ? 'ed25519 signature over the challenge' : 'ed25519 signature does not verify',
    };
  }

  const clientDataBytes = fromHex(assertion.client_data_json);
  const authenticatorData = fromHex(assertion.authenticator_data);
  if (!clientDataBytes || !authenticatorData) {
    return no('clientDataJSON and authenticatorData must both be hex');
  }
  let clientData;
  try {
    clientData = JSON.parse(new TextDecoder().decode(clientDataBytes));
  } catch (e) {
    return no(`clientDataJSON is not JSON: ${e}`);
  }
  if (clientData === null || typeof clientData !== 'object' || Array.isArray(clientData)) {
    return no('clientDataJSON is not an object');
  }
  if (clientData.type !== WEBAUTHN_GET) {
    return no(`clientDataJSON type is ${JSON.stringify(clientData.type)}, expected "webauthn.get"`);
  }
  if (typeof clientData.challenge !== 'string') return no('clientDataJSON has no challenge');
  const signed = fromBase64Url(clientData.challenge);
  if (signed === null) return no('clientDataJSON.challenge is not base64url');
  if (!bytesEqual(signed, challengeBytes)) return no('the approver signed a different challenge');

  const origins = credential.origins ?? [];
  if (origins.length && !origins.includes(clientData.origin)) {
    return no(
      `origin ${JSON.stringify(clientData.origin)} is not one of the approver's allowed origins`,
    );
  }
  if (authenticatorData.length < 37) {
    return no(`authenticatorData is ${authenticatorData.length} bytes, expected at least 37`);
  }
  const rpId = effectiveRpId(credential);
  if (rpId === null) return no("the approver's credential has no rp_id");
  const rpHash = await sha256(utf8(rpId));
  if (!bytesEqual(authenticatorData.subarray(0, 32), rpHash)) {
    return no(`rpIdHash does not match ${JSON.stringify(rpId)}`);
  }
  const flags = authenticatorData[32];
  if (!(flags & FLAG_USER_PRESENT)) return no('the user-present flag is not set');
  if (credential.user_verification && !(flags & FLAG_USER_VERIFIED)) {
    return no('the policy requires user verification and the flag is not set');
  }
  const message = concatBytes([authenticatorData, await sha256(clientDataBytes)]);
  const ok = await p256Verify(credential.public_key, assertion.signature, message);
  return {
    approver_id: assertion.approver_id,
    valid: ok,
    detail: ok ? 'webauthn assertion verified' : 'webauthn signature does not verify',
  };
}

/**
 * Count *distinct* valid approvers against the required quorum.
 *
 * Distinct is the point: five assertions from one approver are one approval. An
 * approver the policy does not name contributes nothing, and a second assertion
 * from an approver who already counted is a retry, not an attack.
 */
export async function verifyQuorum(assertions, challengeBytes, approvers, quorum) {
  const byId = new Map((approvers ?? []).map((a) => [a.id, a]));
  const checks = [];
  const accepted = [];
  for (const assertion of assertions ?? []) {
    const credential = byId.get(assertion?.approver_id);
    if (!credential) {
      checks.push({
        approver_id: assertion?.approver_id ?? '',
        valid: false,
        detail: `${JSON.stringify(assertion?.approver_id)} is not an approver in this policy`,
      });
      continue;
    }
    if (accepted.includes(assertion.approver_id)) {
      checks.push({
        approver_id: assertion.approver_id,
        valid: true,
        detail: 'duplicate assertion, already counted',
      });
      continue;
    }
    const one = await verifyAssertion(assertion, challengeBytes, credential);
    checks.push(one);
    if (one.valid) accepted.push(assertion.approver_id);
  }
  return { quorum, checks, accepted, reached: accepted.length >= quorum };
}

// ─── 9. CBOR — exactly the profile an attestation may use ──────────────────

/**
 * A reader for the subset of RFC 8949 that `docs/ATTESTATION-VERIFY.md`
 * section 2 allows, and a deterministic writer for the one array section 5
 * re-encodes.
 *
 * Deliberately not a general decoder. The document comes from an untrusted
 * party, and a general reader accepts shapes an attestation may not contain —
 * indefinite lengths and duplicate map keys being the two that matter. Every
 * refusal below is a shape a permissive parser would have silently accepted.
 */
export class CborError extends Error {}

const CBOR_MAX_DEPTH = 16;

class CborReader {
  constructor(bytes) {
    this.b = bytes;
    this.i = 0;
  }

  byte() {
    if (this.i >= this.b.length) throw new CborError('truncated CBOR');
    return this.b[this.i++];
  }

  take(n) {
    if (n < 0 || this.i + n > this.b.length) throw new CborError('truncated CBOR');
    const out = this.b.subarray(this.i, this.i + n);
    this.i += n;
    return out;
  }

  /** Head: returns [majorType, argument]. Shortest form enforced. */
  head() {
    const initial = this.byte();
    const major = initial >> 5;
    const info = initial & 0x1f;
    if (major === 7 && info >= 25 && info <= 27) throw new CborError('floats are not allowed');
    if (info < 24) return [major, info];
    if (info === 24) {
      const v = this.byte();
      if (v < 24) throw new CborError('integer not in shortest form');
      return [major, v];
    }
    if (info === 25) {
      const raw = this.take(2);
      const v = (raw[0] << 8) | raw[1];
      if (v <= 0xff) throw new CborError('integer not in shortest form');
      return [major, v];
    }
    if (info === 26) {
      const raw = this.take(4);
      const v = ((raw[0] << 24) >>> 0) + (raw[1] << 16) + (raw[2] << 8) + raw[3];
      if (v <= 0xffff) throw new CborError('integer not in shortest form');
      return [major, v];
    }
    if (info === 27) {
      const raw = this.take(8);
      let v = 0n;
      for (const byte of raw) v = (v << 8n) | BigInt(byte);
      if (v <= 0xffffffffn) throw new CborError('integer not in shortest form');
      if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new CborError('integer too large');
      return [major, Number(v)];
    }
    if (info === 31) throw new CborError('indefinite lengths are not allowed');
    throw new CborError(`reserved additional information ${info}`);
  }

  value(depth = 0) {
    if (depth > CBOR_MAX_DEPTH) throw new CborError('CBOR nested too deeply');
    const [major, arg] = this.head();
    switch (major) {
      case 0:
        return arg;
      case 1:
        return -1 - arg;
      case 2:
        return this.take(arg).slice();
      case 3: {
        const raw = this.take(arg);
        return new TextDecoder('utf-8', { fatal: true }).decode(raw);
      }
      case 4: {
        const out = [];
        for (let i = 0; i < arg; i++) out.push(this.value(depth + 1));
        return out;
      }
      case 5: {
        const map = new Map();
        for (let i = 0; i < arg; i++) {
          const key = this.value(depth + 1);
          if (typeof key !== 'number' && typeof key !== 'string') {
            throw new CborError('map keys must be integers or text strings');
          }
          if (map.has(key)) throw new CborError(`duplicate map key ${JSON.stringify(key)}`);
          map.set(key, this.value(depth + 1));
        }
        return map;
      }
      case 6:
        if (arg !== 18) throw new CborError(`tag ${arg} is not allowed`);
        return this.value(depth + 1);
      case 7:
        if (arg === 20) return false;
        if (arg === 21) return true;
        if (arg === 22) return null;
        throw new CborError(`simple value ${arg} is not allowed`);
      default:
        throw new CborError(`major type ${major} is not allowed`);
    }
  }
}

export function cborLoads(bytes) {
  const reader = new CborReader(bytes);
  const value = reader.value();
  if (reader.i !== bytes.length) throw new CborError('trailing bytes after the CBOR item');
  return value;
}

function cborHead(major, arg) {
  if (arg < 24) return new Uint8Array([(major << 5) | arg]);
  if (arg <= 0xff) return new Uint8Array([(major << 5) | 24, arg]);
  if (arg <= 0xffff) return new Uint8Array([(major << 5) | 25, arg >> 8, arg & 0xff]);
  return new Uint8Array([
    (major << 5) | 26,
    (arg >>> 24) & 0xff,
    (arg >>> 16) & 0xff,
    (arg >>> 8) & 0xff,
    arg & 0xff,
  ]);
}

/** Deterministic encoding (RFC 8949 section 4.2.1) of the subset above. */
export function cborDumps(value) {
  if (value === null) return new Uint8Array([0xf6]);
  if (value === false) return new Uint8Array([0xf4]);
  if (value === true) return new Uint8Array([0xf5]);
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) throw new CborError('floats are not allowed');
    return value >= 0 ? cborHead(0, value) : cborHead(1, -1 - value);
  }
  if (typeof value === 'string') {
    const raw = utf8(value);
    return concatBytes([cborHead(3, raw.length), raw]);
  }
  if (value instanceof Uint8Array) {
    return concatBytes([cborHead(2, value.length), value]);
  }
  if (Array.isArray(value)) {
    return concatBytes([cborHead(4, value.length), ...value.map(cborDumps)]);
  }
  throw new CborError(`cannot encode ${typeof value}`);
}

// ─── 10. DER and X.509 — the four fields a chain check needs ───────────────

/**
 * Web Crypto has no X.509 parser, so here is one for exactly what
 * `attestation.certificate_chain` and `attestation.certificate_validity` read:
 * the `tbsCertificate` byte range (the bytes the signature covers), the issuer
 * and subject as raw DER, the validity window, and the `subjectPublicKeyInfo` to
 * hand to `importKey`. Nothing else is parsed, because nothing else is used, and
 * an ASN.1 reader that parses more is more that can go wrong.
 */
function derRead(bytes, offset) {
  if (offset + 2 > bytes.length) throw new Error('truncated DER');
  const tag = bytes[offset];
  let i = offset + 1;
  let length = bytes[i++];
  if (length & 0x80) {
    const n = length & 0x7f;
    if (n === 0 || n > 4) throw new Error('unsupported DER length');
    length = 0;
    for (let k = 0; k < n; k++) length = length * 256 + bytes[i++];
  }
  if (i + length > bytes.length) throw new Error('DER length runs past the end');
  return { tag, start: offset, contentStart: i, end: i + length, length };
}

/** The full tag-length-value slice, which is what "the issuer DER" means. */
function derTlv(bytes, node) {
  return bytes.subarray(node.start, node.end);
}

function derChildren(bytes, node) {
  const out = [];
  let at = node.contentStart;
  while (at < node.end) {
    const child = derRead(bytes, at);
    out.push(child);
    at = child.end;
  }
  return out;
}

function parseDerTime(bytes, node) {
  const text = new TextDecoder().decode(bytes.subarray(node.contentStart, node.end));
  // UTCTime YYMMDDHHMMSSZ (tag 0x17) or GeneralizedTime YYYYMMDDHHMMSSZ (0x18)
  const m =
    node.tag === 0x17
      ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text)
      : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);
  if (!m) return null;
  let year = Number(m[1]);
  if (node.tag === 0x17) year += year < 50 ? 2000 : 1900;
  return Date.UTC(year, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]));
}

const OID_EC_PUBLIC_KEY = '2a8648ce3d0201';
const OID_P384 = '2b81040022';
const OID_P256 = '2a8648ce3d030107';

/** Parse the fields a chain check reads. Throws on anything it cannot read. */
export function parseCertificate(der) {
  const cert = derRead(der, 0);
  const [tbs, , signatureBits] = derChildren(der, cert);
  const parts = derChildren(der, tbs);
  // [0] EXPLICIT version is optional; when present it is context tag 0xa0.
  let at = parts[0].tag === 0xa0 ? 1 : 0;
  at += 1; // serialNumber
  at += 1; // signature AlgorithmIdentifier
  const issuer = parts[at++];
  const validity = parts[at++];
  const subject = parts[at++];
  const spki = parts[at++];
  const [notBefore, notAfter] = derChildren(der, validity);
  const spkiAlg = derChildren(der, spki)[0];
  const algOids = derChildren(der, spkiAlg).map((n) => toHex(der.subarray(n.contentStart, n.end)));
  return {
    tbsBytes: derTlv(der, tbs),
    issuerDer: derTlv(der, issuer),
    subjectDer: derTlv(der, subject),
    notBefore: parseDerTime(der, notBefore),
    notAfter: parseDerTime(der, notAfter),
    spkiDer: derTlv(der, spki),
    curve: algOids.includes(OID_P384) ? 'P-384' : algOids.includes(OID_P256) ? 'P-256' : null,
    isEc: algOids.includes(OID_EC_PUBLIC_KEY),
    // BIT STRING: skip the unused-bits octet to reach the DER ECDSA signature.
    signature: der.subarray(signatureBits.contentStart + 1, signatureBits.end),
  };
}

export function pemToDer(pem) {
  const body = String(pem)
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '');
  return fromBase64(body);
}

/** The AWS Nitro Enclaves root, embedded. Never fetched: see ATTESTATION-VERIFY section 5. */
export const NITRO_ROOT_G1_PEM = `-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----`;

export const NITRO_ROOT_G1_SHA256 =
  '641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b';

// ─── 11. attestation documents (docs/ATTESTATION-VERIFY.md) ────────────────

export const CHECK_ATT_FORMAT = 'attestation.format';
export const CHECK_ATT_CHAIN = 'attestation.certificate_chain';
export const CHECK_ATT_VALIDITY = 'attestation.certificate_validity';
export const CHECK_ATT_SIGNATURE = 'attestation.signature';
export const CHECK_ATT_TIMESTAMP = 'attestation.timestamp';
export const CHECK_ATT_PCRS = 'attestation.pcrs';
export const CHECK_ATT_DEBUG = 'attestation.debug_mode';
export const CHECK_ATT_PUBLIC_KEY = 'attestation.public_key';
export const CHECK_ATT_USER_DATA = 'attestation.user_data';

export const ATTESTATION_CHECKS = [
  CHECK_ATT_FORMAT,
  CHECK_ATT_CHAIN,
  CHECK_ATT_VALIDITY,
  CHECK_ATT_SIGNATURE,
  CHECK_ATT_TIMESTAMP,
  CHECK_ATT_PCRS,
  CHECK_ATT_DEBUG,
  CHECK_ATT_PUBLIC_KEY,
  CHECK_ATT_USER_DATA,
];

export const ATTESTATION_FORMATS = ['aws-nitro', 'aws-nitro-v1'];

const COSE_ES384 = -35;
const PCR_LENGTHS = [32, 48, 64];

function mapText(map, key) {
  const value = map.get(key);
  if (typeof value !== 'string' || !value) throw new Error(`attestation ${key} must be text`);
  return value;
}

function mapBytes(map, key) {
  const value = map.get(key);
  if (!(value instanceof Uint8Array) || !value.length) {
    throw new Error(`attestation ${key} must be a non-empty byte string`);
  }
  return value;
}

function mapOptionalBytes(map, key) {
  const value = map.get(key);
  if (value === undefined || value === null) return null;
  if (!(value instanceof Uint8Array)) throw new Error(`attestation ${key} must be bytes or null`);
  return value;
}

/** Decode COSE_Sign1 and its CBOR payload. Throws on anything malformed. */
export function parseAttestation(documentBytes) {
  const message = cborLoads(documentBytes);
  if (!Array.isArray(message) || message.length !== 4) {
    throw new Error('COSE_Sign1 is a four-element array');
  }
  const [protectedBytes, unprotected, payloadBytes, signature] = message;
  if (
    !(protectedBytes instanceof Uint8Array) ||
    !(payloadBytes instanceof Uint8Array) ||
    !(signature instanceof Uint8Array)
  ) {
    throw new Error('protected, payload and signature must be byte strings');
  }
  if (!(unprotected instanceof Map)) throw new Error('the unprotected header must be a map');
  const header = cborLoads(protectedBytes);
  if (!(header instanceof Map)) throw new Error('the protected header must be a CBOR map');
  const alg = header.get(1);

  const body = cborLoads(payloadBytes);
  if (!(body instanceof Map)) throw new Error('the payload must be a CBOR map');
  const pcrsRaw = body.get('pcrs');
  if (!(pcrsRaw instanceof Map) || pcrsRaw.size === 0) {
    throw new Error('attestation pcrs must be a non-empty map');
  }
  const pcrs = new Map();
  for (const [index, value] of pcrsRaw) {
    if (typeof index !== 'number' || index < 0 || index > 31) {
      throw new Error('PCR indices are integers 0-31');
    }
    if (!(value instanceof Uint8Array) || !PCR_LENGTHS.includes(value.length)) {
      throw new Error(`PCR${index} must be 32, 48 or 64 bytes`);
    }
    pcrs.set(index, value);
  }
  const cabundle = body.get('cabundle');
  if (!Array.isArray(cabundle) || !cabundle.length) {
    throw new Error('attestation cabundle must be a non-empty array');
  }
  for (const cert of cabundle) {
    if (!(cert instanceof Uint8Array) || !cert.length) {
      throw new Error('every cabundle entry is a byte string');
    }
  }
  const timestamp = body.get('timestamp');
  if (typeof timestamp !== 'number' || !Number.isInteger(timestamp) || timestamp <= 0) {
    throw new Error('attestation timestamp must be a positive integer');
  }
  return {
    alg,
    protectedBytes,
    payloadBytes,
    signature,
    moduleId: mapText(body, 'module_id'),
    digest: mapText(body, 'digest'),
    timestamp,
    pcrs,
    certificate: mapBytes(body, 'certificate'),
    cabundle,
    publicKey: mapOptionalBytes(body, 'public_key'),
    userData: mapOptionalBytes(body, 'user_data'),
    nonce: mapOptionalBytes(body, 'nonce'),
  };
}

function formatCheck(parsed) {
  const problems = [];
  if (parsed.alg !== COSE_ES384) problems.push(`COSE alg is ${parsed.alg}, expected -35 (ES384)`);
  if (parsed.digest !== 'SHA384') problems.push(`digest is ${JSON.stringify(parsed.digest)}`);
  if (parsed.signature.length !== 96) {
    problems.push(`signature is ${parsed.signature.length} bytes, expected 96`);
  }
  return outcome(
    CHECK_ATT_FORMAT,
    problems.length === 0,
    problems.length ? problems.join('; ') : 'COSE_Sign1 with ES384 and a SHA384 payload',
  );
}

async function chainCheck(parsed, trust) {
  const rootDer = pemToDer(trust.rootPem ?? NITRO_ROOT_G1_PEM);
  if (rootDer === null) return { chain: null, check: check(CHECK_ATT_CHAIN, FAIL, 'bad root PEM') };
  if (!bytesEqual(parsed.cabundle[0], rootDer)) {
    return {
      chain: null,
      check: check(
        CHECK_ATT_CHAIN,
        FAIL,
        "the document's first CA certificate is not the pinned root",
      ),
    };
  }
  const derChain = [...parsed.cabundle, parsed.certificate];
  let parsedChain;
  try {
    parsedChain = derChain.map(parseCertificate);
  } catch (e) {
    return { chain: null, check: check(CHECK_ATT_CHAIN, FAIL, `a certificate does not parse: ${e}`) };
  }
  for (let i = 1; i < parsedChain.length; i++) {
    const child = parsedChain[i];
    const parent = parsedChain[i - 1];
    if (!bytesEqual(child.issuerDer, parent.subjectDer)) {
      return {
        chain: parsedChain,
        check: check(CHECK_ATT_CHAIN, FAIL, `certificate ${i} is not issued by certificate ${i - 1}`),
      };
    }
    if (!parent.isEc || parent.curve === null) {
      return {
        chain: parsedChain,
        check: check(CHECK_ATT_CHAIN, FAIL, `certificate ${i - 1} is not an EC key this verifier knows`),
      };
    }
    const size = parent.curve === 'P-384' ? 48 : 32;
    const raw = derSignatureToRaw(child.signature, size);
    let ok = false;
    if (raw !== null) {
      try {
        ok = await ecdsaVerify(
          parent.spkiDer,
          parent.curve,
          parent.curve === 'P-384' ? 'SHA-384' : 'SHA-256',
          raw,
          child.tbsBytes,
        );
      } catch {
        ok = false;
      }
    }
    if (!ok) {
      return {
        chain: parsedChain,
        check: check(CHECK_ATT_CHAIN, FAIL, `certificate ${i}'s signature does not verify`),
      };
    }
  }
  return {
    chain: parsedChain,
    check: outcome(
      CHECK_ATT_CHAIN,
      true,
      `${parsedChain.length} certificates chain to the pinned AWS Nitro root`,
    ),
  };
}

function validityCheck(chain, parsed) {
  if (chain === null) return noData(CHECK_ATT_VALIDITY, 'the chain could not be built');
  // T is the document's own timestamp, not the reader's clock: an NSM leaf lives
  // about three hours and a receipt is read months later.
  const t = parsed.timestamp;
  for (let i = 0; i < chain.length; i++) {
    const cert = chain[i];
    if (cert.notBefore === null || cert.notAfter === null) {
      return check(CHECK_ATT_VALIDITY, FAIL, `certificate ${i} has an unreadable validity window`);
    }
    if (t < cert.notBefore || t > cert.notAfter) {
      return check(
        CHECK_ATT_VALIDITY,
        FAIL,
        `certificate ${i} was not valid at the document's timestamp ` +
          `${new Date(t).toISOString()}`,
      );
    }
  }
  return outcome(
    CHECK_ATT_VALIDITY,
    true,
    `every certificate was valid at ${new Date(t).toISOString()}`,
  );
}

async function signatureCheck(chain, parsed) {
  if (chain === null) return noData(CHECK_ATT_SIGNATURE, 'the chain could not be built');
  const leaf = chain[chain.length - 1];
  if (leaf.curve !== 'P-384') {
    return check(CHECK_ATT_SIGNATURE, FAIL, 'the leaf certificate key is not P-384');
  }
  // RFC 9052 section 4.4: Sig_structure = ["Signature1", protected, aad, payload],
  // re-encoded as deterministic CBOR. Never sliced out of the document.
  const sigStructure = cborDumps([
    'Signature1',
    parsed.protectedBytes,
    new Uint8Array(0),
    parsed.payloadBytes,
  ]);
  let ok = false;
  try {
    ok = await ecdsaVerify(leaf.spkiDer, 'P-384', 'SHA-384', parsed.signature, sigStructure);
  } catch {
    ok = false;
  }
  return outcome(
    CHECK_ATT_SIGNATURE,
    ok,
    ok ? 'the leaf certificate signed this document' : 'the ES384 signature does not verify',
  );
}

function timestampCheck(parsed, trust, nowMs) {
  const age = (nowMs - parsed.timestamp) / 1000;
  if (age < 0) {
    return check(CHECK_ATT_TIMESTAMP, FAIL, `the document is dated ${-age}s after now`);
  }
  const max = trust.maxAgeSeconds;
  if (max === null || max === undefined) {
    return outcome(
      CHECK_ATT_TIMESTAMP,
      true,
      `the document is ${Math.round(age)}s old; no freshness bound was asked for`,
    );
  }
  return outcome(
    CHECK_ATT_TIMESTAMP,
    age <= max,
    `the document is ${Math.round(age)}s old, the bound is ${max}s`,
  );
}

function pcrCheck(parsed, trust) {
  const allow = trust.pcrs ?? {};
  const indices = Object.keys(allow);
  if (!indices.length) {
    return noData(
      CHECK_ATT_PCRS,
      'no PCR allowlist was pinned, so nothing says which enclave this is',
    );
  }
  for (const key of indices) {
    const index = Number(key);
    const expected = String(allow[key]).toLowerCase();
    const actual = parsed.pcrs.get(index);
    if (!actual) return check(CHECK_ATT_PCRS, FAIL, `the document carries no PCR${index}`);
    if (toHex(actual) !== expected) {
      return check(CHECK_ATT_PCRS, FAIL, `PCR${index} is ${toHex(actual)}, expected ${expected}`);
    }
  }
  return outcome(
    CHECK_ATT_PCRS,
    true,
    `PCR${indices.map(Number).sort((a, b) => a - b).join(', PCR')} match the allowlist`,
  );
}

function debugCheck(parsed, trust) {
  if (trust.requireProductionMode === false) {
    return noData(CHECK_ATT_DEBUG, 'the verifier chose not to require production mode');
  }
  const pcr0 = parsed.pcrs.get(0);
  if (!pcr0) return check(CHECK_ATT_DEBUG, FAIL, 'the document carries no PCR0');
  const zeroed = pcr0.every((b) => b === 0);
  return outcome(
    CHECK_ATT_DEBUG,
    !zeroed,
    zeroed
      ? 'PCR0 is all zero: this enclave ran in debug mode and was never measured'
      : 'PCR0 is non-zero, so the enclave was measured',
  );
}

function bindingCheck(name, actual, expected, what) {
  if (expected === null || expected === undefined) {
    return noData(name, `no expected ${what} was supplied, so this document is about no receipt`);
  }
  if (actual === null) {
    return check(name, FAIL, `a ${what} was expected and the document carries none`);
  }
  return outcome(
    name,
    bytesEqual(actual, expected),
    bytesEqual(actual, expected)
      ? `the document's ${what} is the one expected`
      : `the document's ${what} is ${toHex(actual)}, expected ${toHex(expected)}`,
  );
}

/**
 * Verify one attestation document and report all nine checks by name.
 *
 * `trust` is what the *verifier* pinned before it saw the document:
 * `{pcrs, rootPem, maxAgeSeconds, requireProductionMode}`. `now` is an ISO
 * string or epoch milliseconds. `expectedPublicKey` and `expectedUserData` are
 * `Uint8Array`s — for a receipt, `envelope.signer_public_key` and
 * `envelope.policy_hash`, hex-decoded. Leave either out and that binding reports
 * `not_implemented`: a document that vouches for *a* key says nothing about
 * *this* receipt until the two are held together.
 */
export async function verifyAttestation(
  documentBytes,
  { trust = {}, now, expectedPublicKey = null, expectedUserData = null } = {},
) {
  const nowMs = typeof now === 'number' ? now : Date.parse(String(now));
  if (!Number.isFinite(nowMs)) throw new Error('now must be an ISO instant or epoch millis');
  let parsed;
  try {
    parsed = parseAttestation(documentBytes);
  } catch (e) {
    return result(
      ATTESTATION_CHECKS.map((name) =>
        name === CHECK_ATT_FORMAT
          ? check(name, FAIL, String(e && e.message ? e.message : e))
          : noData(name, 'the document could not be parsed'),
      ),
    );
  }
  const { chain, check: chainResult } = await chainCheck(parsed, trust);
  return result([
    formatCheck(parsed),
    chainResult,
    validityCheck(chain, parsed),
    await signatureCheck(chain, parsed),
    timestampCheck(parsed, trust, nowMs),
    pcrCheck(parsed, trust),
    debugCheck(parsed, trust),
    bindingCheck(CHECK_ATT_PUBLIC_KEY, parsed.publicKey, expectedPublicKey, 'public key'),
    bindingCheck(CHECK_ATT_USER_DATA, parsed.userData, expectedUserData, 'user data'),
  ]);
}

// ─── 11a. XRPL primitives: SHAMap, STValidation, manifests ─────────────────
//
// The counterpart to `merkl/core/verify/xrpl.py`, checked against the same
// real testnet fixtures in `merkl/core/vectors/xrpl/cases.json`. No base58
// anywhere — every key this reads comes straight out of a binary field
// already in raw form. See that module's docstring for the full picture.

const XRPL_TX_NODE_PREFIX = fromHex('534e4400'); // "SND\0"
const XRPL_INNER_NODE_PREFIX = fromHex('4d494e00'); // "MIN\0"
const XRPL_VALIDATION_PREFIX = fromHex('56414c00'); // "VAL\0"
const XRPL_MANIFEST_PREFIX = fromHex('4d414e00'); // "MAN\0"
const XRPL_ZERO32 = new Uint8Array(32);

/** The VL length prefix XRPL puts before a blob, then the offset just past it. */
function xrplReadVlLength(data, i) {
  if (i >= data.length) return null;
  const b0 = data[i];
  if (b0 <= 192) return [b0, i + 1];
  if (b0 <= 240) {
    if (i + 1 >= data.length) return null;
    return [193 + (b0 - 193) * 256 + data[i + 1], i + 2];
  }
  if (i + 2 >= data.length) return null;
  return [12481 + (b0 - 241) * 65536 + data[i + 1] * 256 + data[i + 2], i + 3];
}

function xrplEncodeVl(data) {
  const n = data.length;
  if (n <= 192) return concatBytes([new Uint8Array([n]), data]);
  if (n <= 12480) {
    const v = n - 193;
    return concatBytes([new Uint8Array([193 + (v >> 8), v & 0xff]), data]);
  }
  if (n <= 918744) {
    const v = n - 12481;
    return concatBytes([new Uint8Array([241 + (v >> 16), (v >> 8) & 0xff, v & 0xff]), data]);
  }
  throw new Error('blob too long for XRPL VL encoding');
}

// Only the field types that appear in an STValidation or a manifest (see
// rippled's SOTemplate for each): fixed-width integers/hashes, VL-encoded
// blobs and Vector256, and the always-8-byte native (XRP) form of Amount.
const XRPL_FIXED_WIDTH = { 16: 1, 1: 2, 2: 4, 3: 8, 4: 16, 17: 20, 20: 12, 5: 32, 21: 24, 22: 48, 23: 64 };
const XRPL_VL_ENCODED = new Set([7, 19]);
const XRPL_AMOUNT_TYPE = 6;

/** Walk a serialized top-level object into `{typeCode, fieldCode, start, end, valueStart}` spans. */
function xrplParseFields(data) {
  const fields = [];
  let i = 0;
  const n = data.length;
  while (i < n) {
    const start = i;
    let header = data[i++];
    let typeCode = header >> 4;
    let fieldCode = header & 0x0f;
    if (typeCode === 0) typeCode = data[i++];
    if (fieldCode === 0) fieldCode = data[i++];
    let valueStart;
    if (XRPL_VL_ENCODED.has(typeCode)) {
      const lenResult = xrplReadVlLength(data, i);
      if (lenResult === null) throw new Error(`truncated VL length prefix at offset ${start}`);
      const [length, afterLen] = lenResult;
      valueStart = afterLen;
      i = afterLen + length;
    } else if (typeCode === XRPL_AMOUNT_TYPE) {
      if (i >= n) throw new Error(`truncated field (${typeCode},${fieldCode}) at offset ${start}`);
      if ((data[i] & 0x80) !== 0) {
        throw new Error(
          `field (${typeCode},${fieldCode}) at offset ${start} is a non-native Amount, which ` +
            'never appears in a Validation or Manifest object',
        );
      }
      valueStart = i;
      i += 8;
    } else {
      const width = XRPL_FIXED_WIDTH[typeCode];
      if (width === undefined) {
        throw new Error(`field (${typeCode},${fieldCode}) at offset ${start} has an unsupported type`);
      }
      valueStart = i;
      i += width;
    }
    if (i > n) throw new Error(`field (${typeCode},${fieldCode}) at offset ${start} is truncated`);
    fields.push({ typeCode, fieldCode, start, end: i, valueStart });
  }
  return fields;
}

/** `data` with the given `[typeCode, fieldCode]` spans excised, order preserved. */
function xrplSigningPreimage(data, fields, exclude) {
  const chunks = [];
  for (const f of fields) {
    if (!exclude.some(([t, c]) => t === f.typeCode && c === f.fieldCode)) {
      chunks.push(data.subarray(f.start, f.end));
    }
  }
  return concatBytes(chunks);
}

function xrplField(fields, data, typeCode, fieldCode) {
  for (const f of fields) {
    if (f.typeCode === typeCode && f.fieldCode === fieldCode) return data.subarray(f.valueStart, f.end);
  }
  return null;
}

/** 0xED means Ed25519 (raw message), 0x02/0x03 means secp256k1 (SHA-512Half digest). */
async function xrplVerifyGeneric(publicKey, signature, message) {
  if (publicKey.length !== 33) throw new Error(`public key must be 33 bytes, got ${publicKey.length}`);
  if (publicKey[0] === 0xed) {
    return (await ed25519Verify(toHex(publicKey.subarray(1)), toHex(signature), message)) === true;
  }
  if (publicKey[0] === 2 || publicKey[0] === 3) {
    return secp256k1VerifyDigest(toHex(publicKey), toHex(signature), await sha512Half(message));
  }
  throw new Error(`public key has an unrecognized prefix byte 0x${publicKey[0].toString(16)}`);
}

/** A transaction-with-metadata SHAMap leaf's hash: `SHA-512Half("SND\0" ‖ VL(tx) ‖ VL(meta) ‖ id)`. */
async function xrplTxLeafHash(txId, txBlob, metaBlob) {
  if (txId.length !== 32) throw new Error(`tx id must be 32 bytes, got ${txId.length}`);
  return sha512Half(
    concatBytes([XRPL_TX_NODE_PREFIX, xrplEncodeVl(txBlob), xrplEncodeVl(metaBlob), txId]),
  );
}

/** A SHAMap inner node's hash: 16 children, empty branches zeroed. */
async function xrplInnerNodeHash(children) {
  if (children.length !== 16) throw new Error('a SHAMap inner node has 16 branches');
  if (children.every((c) => bytesEqual(c, XRPL_ZERO32))) return XRPL_ZERO32;
  return sha512Half(concatBytes([XRPL_INNER_NODE_PREFIX, ...children]));
}

/**
 * Recompute a SHAMap root from a leaf and its path. `null` on anything malformed.
 *
 * Recomputes the leaf from the transaction's own raw bytes (so the path is
 * tied to *this* transaction's content) and folds `steps` leaf-to-root —
 * see `merkl.core.verify.xrpl.fold_tx_path`, the Python counterpart.
 */
export async function xrplFoldTxPath(txIdHex, txBlobHex, metaHex, steps) {
  try {
    let current = await xrplTxLeafHash(fromHex(txIdHex), fromHex(txBlobHex), fromHex(metaHex));
    for (const step of steps) {
      const nibble = step && step.nibble;
      const siblings = step && step.siblings;
      if (!Number.isInteger(nibble) || nibble < 0 || nibble > 15) return null;
      if (!Array.isArray(siblings) || siblings.length !== 15) return null;
      const children = new Array(16).fill(XRPL_ZERO32);
      children[nibble] = current;
      let idx = 0;
      for (let branch = 0; branch < 16; branch++) {
        if (branch === nibble) continue;
        const sibling = fromHex(siblings[idx++]);
        if (sibling === null || sibling.length !== 32) return null;
        children[branch] = sibling;
      }
      current = await xrplInnerNodeHash(children);
    }
    return toHex(current);
  } catch {
    return null;
  }
}

/** Fields, `LedgerHash`, `SigningPubKey` and `Signature` — raw bytes. Throws if any is missing. */
function xrplParseValidation(data) {
  const fields = xrplParseFields(data);
  const ledgerHash = xrplField(fields, data, 5, 1); // Hash256 LedgerHash, nth 1
  const signingKey = xrplField(fields, data, 7, 3); // Blob SigningPubKey, nth 3
  const signature = xrplField(fields, data, 7, 6); // Blob Signature, nth 6
  if (ledgerHash === null || signingKey === null || signature === null) {
    throw new Error('validation is missing LedgerHash, SigningPubKey or Signature');
  }
  return { fields, ledgerHash, signingKey, signature };
}

/** Recompute the signing hash and check `Signature` against `SigningPubKey`. */
async function xrplVerifyValidation(data) {
  const { fields, ledgerHash, signingKey, signature } = xrplParseValidation(data);
  const preimage = xrplSigningPreimage(data, fields, [[7, 6]]);
  const valid = await xrplVerifyGeneric(
    signingKey,
    signature,
    concatBytes([XRPL_VALIDATION_PREFIX, preimage]),
  );
  const ledgerSeq = xrplField(fields, data, 2, 6); // UInt32 LedgerSequence, nth 6
  return {
    ledgerHash: toHex(ledgerHash),
    signingKey: toHex(signingKey),
    signatureValid: valid,
    ledgerIndex: ledgerSeq ? Number(bytesToBigInt(ledgerSeq)) : null,
  };
}

/** Fields, sequence, master key, ephemeral key, signature, master signature, domain. Throws if malformed. */
function xrplParseManifest(data) {
  const fields = xrplParseFields(data);
  const sequence = xrplField(fields, data, 2, 4); // UInt32 Sequence, nth 4
  const masterKey = xrplField(fields, data, 7, 1); // Blob PublicKey, nth 1
  const signingKey = xrplField(fields, data, 7, 3); // Blob SigningPubKey, nth 3
  const signature = xrplField(fields, data, 7, 6); // Blob Signature, nth 6
  const masterSignature = xrplField(fields, data, 7, 18); // Blob MasterSignature, nth 18
  const domain = xrplField(fields, data, 7, 7); // Blob Domain, nth 7 (optional)
  if (sequence === null || masterKey === null || signingKey === null) {
    throw new Error('manifest is missing Sequence, PublicKey or SigningPubKey');
  }
  if (signature === null || masterSignature === null) {
    throw new Error('manifest is missing Signature or MasterSignature');
  }
  return { fields, sequence, masterKey, signingKey, signature, masterSignature, domain };
}

/** Recompute the manifest's signing hash and check both signatures against it. */
async function xrplVerifyManifest(data) {
  const { fields, sequence, masterKey, signingKey, signature, masterSignature, domain } =
    xrplParseManifest(data);
  const preimage = xrplSigningPreimage(data, fields, [
    [7, 6],
    [7, 18],
  ]);
  const message = concatBytes([XRPL_MANIFEST_PREFIX, preimage]);
  const masterOk = await xrplVerifyGeneric(masterKey, masterSignature, message);
  const ephemeralOk = await xrplVerifyGeneric(signingKey, signature, message);
  return {
    sequence: Number(bytesToBigInt(sequence)),
    masterKey: toHex(masterKey),
    signingKey: toHex(signingKey),
    domain: domain ? new TextDecoder().decode(domain) : null,
    masterSignatureValid: masterOk,
    ephemeralSignatureValid: ephemeralOk,
    valid: masterOk && ephemeralOk,
  };
}

/**
 * Does this captured validation entry count as a pinned validator's agreement?
 *
 * `null` when the entry cannot be attributed to any *pinned* master key —
 * not evidence either way. See `merkl.core.verify.xrpl.evaluate_validation`,
 * the Python counterpart this must agree with over the same fixtures.
 */
export async function evaluateXrplValidation(entry, ledgerHash, pinnedMasters) {
  const raw = entry && entry.data;
  if (typeof raw !== 'string' || !raw) {
    return { outcome: 'unchecked', masterKey: null, detail: 'the entry carries no raw validation data' };
  }
  let validation;
  try {
    validation = await xrplVerifyValidation(fromHex(raw));
  } catch (e) {
    return { outcome: 'unchecked', masterKey: null, detail: `the validation does not parse: ${e.message}` };
  }
  const manifestB64 = entry.manifest;
  if (typeof manifestB64 !== 'string' || !manifestB64) {
    return {
      outcome: 'unchecked',
      masterKey: null,
      detail: `no manifest was captured for signing key ${validation.signingKey}`,
    };
  }
  let manifest;
  try {
    manifest = await xrplVerifyManifest(fromBase64(manifestB64));
  } catch (e) {
    return { outcome: 'unchecked', masterKey: null, detail: `the manifest does not parse: ${e.message}` };
  }
  const master = manifest.masterKey.toLowerCase();
  const pinnedLower = new Set([...pinnedMasters].map((m) => m.toLowerCase()));
  if (!pinnedLower.has(master)) return null;
  if (!manifest.valid) {
    return { outcome: 'unchecked', masterKey: master, detail: `validator ${master}'s manifest does not verify` };
  }
  if (manifest.signingKey.toLowerCase() !== validation.signingKey.toLowerCase()) {
    return {
      outcome: 'unchecked',
      masterKey: master,
      detail: `validator ${master}'s pinned manifest names a different ephemeral key`,
    };
  }
  if (validation.ledgerHash.toLowerCase() !== ledgerHash.toLowerCase()) {
    return { outcome: 'disagree', masterKey: master, detail: `validator ${master} signed a different ledger hash` };
  }
  if (!validation.signatureValid) {
    return { outcome: 'disagree', masterKey: master, detail: `validator ${master}'s signature does not verify` };
  }
  return { outcome: 'agree', masterKey: master, detail: `validator ${master} signed ledger ${ledgerHash}` };
}

// ─── 12. settlement proofs (plan D20, spec section 7.2) ────────────────────

export const CHECK_PROOF_MATCHES = 'settlement.proof_matches_receipt';
export const CHECK_LEDGER_HEADER = 'settlement.ledger_header';
export const CHECK_VALIDATOR_QUORUM = 'settlement.validator_quorum';

export const LEDGER_PROVEN_OFFLINE = 'proven-offline';
export const LEDGER_VERIFIED_LIVE = 'verified-live';
export const LEDGER_SUPPLIED_UNVERIFIED = 'supplied-unverified';
export const LEDGER_UNCHECKED = 'unchecked';

export const RAIL_XRPL = 'xrpl';
export const RAIL_FAKE = 'fake';

const XRPL_LEDGER_PREFIX = new Uint8Array([0x4c, 0x57, 0x52, 0x00]); // "LWR\0"
const FAKE_LEDGER_TAG = utf8('merkl-fake-ledger-v1');
const FAKE_VALIDATION_TAG = utf8('merkl-fake-validation-v1');

function hash32(value) {
  const raw = fromHex(value);
  if (raw === null || raw.length !== 32) throw new Error('expected a 32-byte hex value');
  return raw;
}

function uint(value, size) {
  if (value === null || value === undefined || value === '' || typeof value === 'boolean') {
    throw new Error('expected an integer');
  }
  const n = BigInt(value);
  if (n < 0n) throw new Error('expected a non-negative integer');
  return uintBE(n, size);
}

/** The ledger hash XRPL derives from a ledger header, lowercase hex. */
export async function xrplLedgerHash(header) {
  const index = header.ledger_index ?? header.seq;
  const body = concatBytes([
    XRPL_LEDGER_PREFIX,
    uint(index, 4),
    uint(header.total_coins, 8),
    hash32(header.parent_hash),
    hash32(header.transaction_hash),
    hash32(header.account_hash),
    uint(header.parent_close_time, 4),
    uint(header.close_time, 4),
    uint(header.close_time_resolution, 1),
    uint(header.close_flags, 1),
  ]);
  return toHex(await sha512Half(body));
}

/** The fake rail's ledger identity. Not a real rail's encoding; see spec 7.2. */
export async function fakeLedgerHash(header) {
  const body = concatBytes([
    FAKE_LEDGER_TAG,
    NUL_BYTE,
    uint(header.ledger_index, 8),
    hash32(header.transaction_hash),
  ]);
  return toHex(await sha256(body));
}

export const LEDGER_HASH_RULES = { [RAIL_XRPL]: xrplLedgerHash, [RAIL_FAKE]: fakeLedgerHash };

/** The bytes a fake-rail validator signs. */
export function fakeValidationMessage(ledgerHash, ledgerIndex) {
  return concatBytes([FAKE_VALIDATION_TAG, NUL_BYTE, hash32(ledgerHash), uint(ledgerIndex, 8)]);
}

export const VALIDATION_MESSAGE_RULES = { [RAIL_FAKE]: fakeValidationMessage };

/** Fold a transaction id up the fake rail's toy binary tree. `null` when malformed. */
function fakeTxPathRoot(txHashLower, path) {
  return deriveRoot(txHashLower, path.siblings, path.directions);
}

/** Fold a transaction up XRPL's real 16-ary SHAMap. `null` when malformed. */
function xrplTxPathRoot(txHashLower, path) {
  const { tx_blob: txBlob, tx_meta: txMeta, steps } = path;
  if (typeof txBlob !== 'string' || typeof txMeta !== 'string' || !Array.isArray(steps)) return null;
  return xrplFoldTxPath(txHashLower, txBlob, txMeta, steps);
}

/** Rails whose transaction-set path this verifier can fold back to a root. */
export const TX_PATH_ROOT_RULES = { [RAIL_FAKE]: fakeTxPathRoot, [RAIL_XRPL]: xrplTxPathRoot };

function validatorId(entry) {
  for (const key of ['validator', 'validation_public_key', 'master_key', 'signing_key']) {
    if (typeof entry[key] === 'string' && entry[key]) return entry[key];
  }
  return null;
}

function proofMatchesCheck(proof, rail, txHash, ledgerIndex) {
  const proofTx = proof.tx_hash;
  if (typeof proofTx !== 'string' || proofTx.toLowerCase() !== String(txHash).toLowerCase()) {
    return check(
      CHECK_PROOF_MATCHES,
      FAIL,
      `the proof is for transaction ${JSON.stringify(proofTx)}, the receipt names ${txHash}`,
    );
  }
  if (proof.rail !== rail) {
    return check(
      CHECK_PROOF_MATCHES,
      FAIL,
      `the proof is for rail ${JSON.stringify(proof.rail)}, the receipt names ` +
        `${JSON.stringify(rail)}`,
    );
  }
  if (ledgerIndex !== null && ledgerIndex !== undefined && proof.ledger_index !== ledgerIndex) {
    return check(
      CHECK_PROOF_MATCHES,
      FAIL,
      `the proof is for ledger ${proof.ledger_index}, the receipt names ${ledgerIndex}`,
    );
  }
  return outcome(
    CHECK_PROOF_MATCHES,
    true,
    `the proof is about ${rail} transaction ${txHash} in ledger ${proof.ledger_index}`,
  );
}

async function ledgerHeaderCheck(proof, rail) {
  const header = proof.ledger_header;
  const claimed = typeof proof.ledger_hash === 'string' ? proof.ledger_hash : null;
  const rule = LEDGER_HASH_RULES[rail];
  if (!rule) {
    return [
      noData(CHECK_LEDGER_HEADER, `this verifier has no ledger-hash rule for rail "${rail}"`),
      claimed,
    ];
  }
  if (header === null || typeof header !== 'object' || Array.isArray(header)) {
    return [noData(CHECK_LEDGER_HEADER, 'the proof carries no ledger header'), claimed];
  }
  let derived;
  try {
    derived = await rule(header);
  } catch (e) {
    return [check(CHECK_LEDGER_HEADER, FAIL, `the ledger header does not hash: ${e.message}`), null];
  }
  if (!claimed) {
    return [
      outcome(
        CHECK_LEDGER_HEADER,
        true,
        `the header hashes to ${derived}; the proof names no ledger hash to compare`,
      ),
      derived,
    ];
  }
  return [
    outcome(
      CHECK_LEDGER_HEADER,
      derived.toLowerCase() === claimed.toLowerCase(),
      `the header hashes to ${derived}, the proof names ${claimed.toLowerCase()}`,
    ),
    derived,
  ];
}

/**
 * Count *pinned master keys* whose manifest-verified ephemeral key signed this ledger.
 *
 * Every link is checked by `evaluateXrplValidation`: the manifest's own two
 * signatures, that its ephemeral key is the one that actually signed this
 * validation, and that signature itself. A validator nobody pinned returns
 * `null` and does not count either way.
 */
async function xrplQuorumCheck(ledgerHash, trust, entries) {
  const agreed = new Set();
  const disagreed = [];
  let unchecked = 0;
  for (const entry of entries) {
    const verdict = await evaluateXrplValidation(entry, ledgerHash, Object.keys(trust.validators));
    if (verdict === null) continue;
    if (verdict.outcome === 'agree' && verdict.masterKey !== null) agreed.add(verdict.masterKey);
    else if (verdict.outcome === 'disagree') disagreed.push(verdict.masterKey || '(unknown)');
    else unchecked++;
  }
  const total = Object.keys(trust.validators).length;
  if (disagreed.length) {
    const names = [...new Set(disagreed)].sort().slice(0, 4).join(', ');
    return check(
      CHECK_VALIDATOR_QUORUM,
      FAIL,
      `${disagreed.length} pinned validator(s) did not sign ${ledgerHash}: ${names}`,
    );
  }
  if (agreed.size >= trust.quorum) {
    return outcome(
      CHECK_VALIDATOR_QUORUM,
      true,
      `${agreed.size} of ${total} pinned validators signed ledger ${ledgerHash}, quorum is ${trust.quorum}`,
    );
  }
  if (unchecked) {
    return noData(
      CHECK_VALIDATOR_QUORUM,
      `${agreed.size} of ${total} pinned validators verified, ${unchecked} more validation ` +
        'entries did not carry enough evidence (a raw validation blob and a manifest for it) ' +
        'to check — agreement counted, not proved',
    );
  }
  return outcome(
    CHECK_VALIDATOR_QUORUM,
    false,
    `${agreed.size} of ${total} pinned validators signed ledger ${ledgerHash}, quorum is ${trust.quorum}`,
  );
}

async function validatorQuorumCheck(proof, ledgerHash, trust, rail) {
  if (!trust || !trust.validators || !Object.keys(trust.validators).length) {
    return noData(
      CHECK_VALIDATOR_QUORUM,
      'no validator key set was pinned, so nothing says whose agreement would count',
    );
  }
  const entries = Array.isArray(proof.validations)
    ? proof.validations.filter((v) => v && typeof v === 'object' && !Array.isArray(v))
    : [];
  if (!entries.length) {
    return noData(CHECK_VALIDATOR_QUORUM, 'the capture carries no validation messages');
  }
  if (ledgerHash === null) {
    return noData(CHECK_VALIDATOR_QUORUM, 'there is no ledger hash for the validations to agree about');
  }
  if (rail === RAIL_XRPL) {
    return xrplQuorumCheck(ledgerHash, trust, entries);
  }
  const rule = VALIDATION_MESSAGE_RULES[rail];
  const agreed = new Set();
  const unchecked = new Set();
  const disagreed = [];
  for (const entry of entries) {
    const name = validatorId(entry);
    if (name === null || !(name in trust.validators)) continue;
    const claimed = entry.ledger_hash;
    if (typeof claimed !== 'string' || claimed.toLowerCase() !== ledgerHash.toLowerCase()) {
      disagreed.push(name);
      continue;
    }
    const key = trust.validators[name];
    const signature = entry.signature;
    const index = entry.ledger_index;
    if (!rule || !key || typeof signature !== 'string' || !Number.isInteger(index)) {
      unchecked.add(name);
      continue;
    }
    let valid = false;
    try {
      valid = (await ed25519Verify(key, signature, rule(claimed, index))) === true;
    } catch {
      valid = false;
    }
    if (valid) agreed.add(name);
    else disagreed.push(name);
  }
  const total = Object.keys(trust.validators).length;
  if (disagreed.length) {
    const names = [...new Set(disagreed)].sort().slice(0, 4).join(', ');
    return check(
      CHECK_VALIDATOR_QUORUM,
      FAIL,
      `${disagreed.length} pinned validator(s) did not sign ${ledgerHash}: ${names}`,
    );
  }
  if (unchecked.size) {
    return noData(
      CHECK_VALIDATOR_QUORUM,
      `${unchecked.size} of ${total} pinned validators named this ledger, but the capture ` +
        'carries no signature this verifier can check — agreement counted, not proved',
    );
  }
  return outcome(
    CHECK_VALIDATOR_QUORUM,
    agreed.size >= trust.quorum,
    `${agreed.size} of ${total} pinned validators signed ledger ${ledgerHash}, ` +
      `quorum is ${trust.quorum}`,
  );
}

/** Read a settlement proof and say exactly how far it gets. */
export async function readSettlementProof(
  proof,
  { rail, txHash, ledgerIndex = null, trust = null, live = false } = {},
) {
  if (proof === null || typeof proof !== 'object' || Array.isArray(proof)) {
    return {
      checks: [
        noData(CHECK_PROOF_MATCHES, 'no settlement proof was supplied'),
        noData(CHECK_LEDGER_HEADER, 'no settlement proof was supplied'),
        noData(CHECK_VALIDATOR_QUORUM, 'no settlement proof was supplied'),
      ],
      ledger_inclusion: live ? LEDGER_VERIFIED_LIVE : LEDGER_UNCHECKED,
      detail: live
        ? 'a live rail query reported this transaction validated'
        : 'no settlement proof was supplied with this receipt',
    };
  }
  const match = proofMatchesCheck(proof, rail, txHash, ledgerIndex);
  const [header, ledgerHash] = await ledgerHeaderCheck(proof, rail);
  const quorum = await validatorQuorumCheck(proof, ledgerHash, trust, rail);
  const checks = [match, header, quorum];

  const missing = Array.isArray(proof.missing) ? proof.missing.filter((m) => typeof m === 'string') : [];
  const headerMap = proof.ledger_header;
  const txRoot =
    headerMap && typeof headerMap === 'object' && typeof headerMap.transaction_hash === 'string'
      ? headerMap.transaction_hash
      : null;
  const path = proof.tx_path;
  let pathOk = false;
  let pathDetail = "the proof carries no path from this transaction to the ledger's transaction set";
  if (path && typeof path === 'object' && txRoot !== null) {
    const rule = TX_PATH_ROOT_RULES[rail];
    const derived = rule ? await rule(String(txHash).toLowerCase(), path) : null;
    pathOk = derived !== null && derived.toLowerCase() === txRoot.toLowerCase();
    pathDetail = pathOk
      ? `the transaction folds to the header's transaction root ${txRoot.toLowerCase()}`
      : `the supplied path folds to ${derived}, the header names ${txRoot.toLowerCase()}`;
  }

  if (match.status === FAIL) {
    return { checks, ledger_inclusion: LEDGER_SUPPLIED_UNVERIFIED, detail: match.detail };
  }
  if (pathOk && header.status === PASS && quorum.status === PASS && !missing.includes('shamap_path')) {
    return {
      checks,
      ledger_inclusion: LEDGER_PROVEN_OFFLINE,
      detail: `${quorum.detail}; ${pathDetail}`,
    };
  }
  if (live) {
    return {
      checks,
      ledger_inclusion: LEDGER_VERIFIED_LIVE,
      detail: 'a live rail query reported this transaction validated',
    };
  }
  const gaps = missing.length ? missing.join(', ') : pathDetail;
  return {
    checks,
    ledger_inclusion: LEDGER_SUPPLIED_UNVERIFIED,
    detail: `the capture does not prove inclusion offline; missing: ${gaps}`,
  };
}

// ─── 13. the receipt verdict ───────────────────────────────────────────────

export const CHECK_VERSION = 'receipt.version';
export const CHECK_LEAF_COUNT = 'leaves.count';
export const CHECK_REQUIRED_LEAVES = 'leaves.required_present';
export const CHECK_PADDING = 'leaves.padding';
export const CHECK_LEFT = 'commitment.left';
export const CHECK_RIGHT = 'commitment.right';
export const CHECK_ROOT = 'commitment.root';
export const CHECK_POLICY_DOCUMENT = 'policy.document';
export const CHECK_ESCALATION_CHALLENGE = 'policy.escalation_challenge';
export const CHECK_APPROVAL_QUORUM = 'policy.approval_quorum';
export const CHECK_POLICY_SIGNATURE = 'policy.signature';
export const CHECK_ATTESTATION = 'signer.attestation';
export const CHECK_INTENT_MATCHES = 'intent.matches_settled_fields';
export const CHECK_ANCHOR = 'settlement.anchor_equals_left';
export const CHECK_SIGNED_BLOB = 'settlement.signed_blob';
export const CHECK_LEDGER_INCLUSION = 'settlement.ledger_inclusion';
export const CHECK_ENVELOPE_RAIL = 'envelope.rail';
export const CHECK_ENVELOPE_TREASURY = 'envelope.treasury';
export const CHECK_ENVELOPE_POLICY_HASH = 'envelope.policy_hash';
export const CHECK_LOG_JOIN = 'session.log_join';

export const AUTHORIZATION_VERIFIED = 'verified';
export const AUTHORIZATION_ABSENT = 'absent';
export const AUTHORIZATION_CONTRADICTED = 'contradicted';

export const LEVEL_RECEIPT = 1;
export const LEVEL_SESSION = 2;

const POLICY_TAG = utf8('merkl-policy-v1');
const XRPL_TX_PREFIX = new Uint8Array([0x54, 0x58, 0x4e, 0x00]); // "TXN\0"
const FAKE_TX_TAG = utf8('merkl-fake-tx-v1');

/** Re-derive a transaction id from its signed blob, or null for an unknown rail. */
export async function txIdFromBlob(rail, signedBlobHex) {
  const blob = fromHex(signedBlobHex);
  if (blob === null) return null;
  if (rail === RAIL_XRPL) return toHex(await sha512Half(concatBytes([XRPL_TX_PREFIX, blob]))).toUpperCase();
  if (rail === RAIL_FAKE) {
    return toHex(await sha256(concatBytes([FAKE_TX_TAG, NUL_BYTE, blob]))).toUpperCase();
  }
  return null;
}

/** `SHA-256("merkl-policy-v1" || NUL || canonical(document))`, lowercase hex. */
export async function policyHash(document) {
  return toHex(await sha256(concatBytes([POLICY_TAG, NUL_BYTE, utf8(canonicalJson(document))])));
}

const ADMIN_APPROVER_ID = 'admin';

function effectiveAdmin(document) {
  if (document && document.admin) return document.admin;
  return { credential_type: 'ed25519', public_key: document ? document.admin_public_key : null };
}

/**
 * `true`, `false`, or `null` when this runtime cannot check the algorithm
 * involved (no Ed25519 in Web Crypto). Shared by `verifyPolicySignature` and
 * `policyDocumentCheck`, which need the same verification but disagree on
 * what to do with `null` — a public boolean utility collapses it to `false`,
 * a receipt check reports it as `not_implemented` rather than a quiet fail.
 */
async function policySignatureOutcome(signed, pinned) {
  const document = signed.document;
  if (signed.signer_public_key !== pinned.public_key) return false;

  if (typeof signed.signature === 'string') {
    if (pinned.credential_type !== 'ed25519') return false;
    const preImage = concatBytes([POLICY_TAG, NUL_BYTE, utf8(canonicalJson(document))]);
    return await ed25519Verify(signed.signer_public_key, signed.signature, preImage);
  }

  const assertion = signed.signature;
  if (!assertion || typeof assertion !== 'object' || assertion.approver_id !== ADMIN_APPROVER_ID) {
    return false;
  }
  const credential = {
    id: ADMIN_APPROVER_ID,
    credential_type: pinned.credential_type,
    public_key: pinned.public_key,
    origins: pinned.origins ?? [],
    rp_id: pinned.rp_id ?? null,
    user_verification: pinned.user_verification ?? false,
  };
  const digest = fromHex(await policyHash(document));
  const result = await verifyAssertion(assertion, digest, credential);
  if (result.unsupported) return null;
  return result.valid;
}

/**
 * Verify a `SignedPolicy`'s admin signature (plan D16, extended).
 *
 * Mirrors `merkl.core.policy.approvals.verify_policy_signature` exactly.
 * `signed.signature` is either the legacy raw Ed25519 hex over the tagged
 * pre-image, or an `ApprovalAssertion`-shaped object (Ed25519 or WebAuthn) over
 * the 32-byte `policy_hash` — the exact challenge a WebAuthn admin credential
 * signs, checked with the same `verifyAssertion` an approver's assertion is
 * checked with. No second WebAuthn parser for the admin role.
 *
 * `admin` pins a full credential, a WebAuthn admin's `origins` included;
 * `adminPublicKey` pins a legacy Ed25519 key only. Passing neither trusts the
 * document's own `admin` / `admin_public_key` member — exactly what a forged
 * document exploits by nominating itself, so a real policy update should
 * always pin one.
 *
 * Returns `{valid, detail}`, like `verifyAssertion` — nothing in this package
 * returns a single boolean. A runtime with no Ed25519 in Web Crypto comes back
 * `valid: false` with `unsupported: true`, the same convention `verifyAssertion`
 * uses, rather than a quiet failure.
 */
export async function verifyPolicySignature(signed, { adminPublicKey = null, admin = null } = {}) {
  if (admin && adminPublicKey) {
    throw new Error('pass admin or adminPublicKey to verifyPolicySignature, not both');
  }
  const pinned =
    admin ??
    (adminPublicKey
      ? { credential_type: 'ed25519', public_key: adminPublicKey }
      : effectiveAdmin(signed.document));
  const outcome = await policySignatureOutcome(signed, pinned);
  if (outcome === null) {
    return {
      valid: false,
      detail: 'this runtime has no Ed25519 in Web Crypto, so the policy signature is unchecked',
      unsupported: true,
    };
  }
  return {
    valid: outcome === true,
    detail: outcome
      ? 'the admin credential signed this policy'
      : "the policy document's admin signature does not verify",
  };
}

function member(content, key) {
  return content && typeof content === 'object' && !Array.isArray(content) ? content[key] : null;
}

function contentAt(contents, index) {
  return index < contents.length ? contents[index] : null;
}

// -- the checks that need only the receipt ---------------------------------

async function leafChecks(envelope, contents) {
  const committed = envelope.leaf_hashes ?? [];
  const checks = [];
  const computed = [];
  for (let i = 0; i < LEAF_NAMES.length; i++) {
    const name = LEAF_NAMES[i];
    if (i >= contents.length) {
      computed.push(null);
      checks.push(check(`leaf.${name}`, FAIL, 'leaf content missing'));
      continue;
    }
    let digest = null;
    try {
      digest = await receiptLeafHash(name, contents[i]);
    } catch (e) {
      computed.push(null);
      checks.push(check(`leaf.${name}`, FAIL, String(e)));
      continue;
    }
    computed.push(digest);
    checks.push(
      outcome(
        `leaf.${name}`,
        digest === committed[i],
        `recomputed ${digest} vs committed ${committed[i]}`,
      ),
    );
  }
  return { checks, computed };
}

function policySignatureCheck(settlement, envelope) {
  if (settlement === null) {
    return noData(CHECK_POLICY_SIGNATURE, 'nothing settled, so there is no policy signature to check');
  }
  const signature = member(settlement, 'policy_signature');
  if (!signature) {
    return check(
      CHECK_POLICY_SIGNATURE,
      FAIL,
      'a settled receipt must carry the policy signature that authorized it',
    );
  }
  if (signature.public_key !== envelope.signer_public_key) {
    return check(CHECK_POLICY_SIGNATURE, FAIL, 'signed by a key the envelope does not name');
  }
  if (signature.algorithm !== 'ed25519') {
    return noData(
      CHECK_POLICY_SIGNATURE,
      `this verifier only knows ed25519, the receipt says "${signature.algorithm}"`,
    );
  }
  return null; // the cryptographic half runs async, below
}

async function finishPolicySignature(settlement, envelope) {
  const signature = member(settlement, 'policy_signature');
  const payload = fromHex(signature.payload);
  if (payload === null) return check(CHECK_POLICY_SIGNATURE, FAIL, 'the signed payload is not hex');
  if (!toHex(payload).includes(String(envelope.left).toLowerCase())) {
    return check(
      CHECK_POLICY_SIGNATURE,
      FAIL,
      'the signed payload does not contain LEFT, so the signature authorizes ' +
        'something other than this receipt',
    );
  }
  const ok = await ed25519Verify(signature.public_key, signature.signature, payload);
  if (ok === null) {
    return noData(
      CHECK_POLICY_SIGNATURE,
      'this runtime has no Ed25519 in Web Crypto, so the policy signature is unchecked',
    );
  }
  return outcome(
    CHECK_POLICY_SIGNATURE,
    ok,
    ok
      ? 'the policy key signed a payload carrying LEFT'
      : 'the policy signature does not verify',
  );
}

async function attestationCheck(content, envelope, trust, now) {
  if (content === null || content === undefined) {
    return noData(
      CHECK_ATTESTATION,
      'leaf 3 is null: this receipt proves it was produced by an unattested signer',
    );
  }
  const format = member(content, 'format');
  if (!ATTESTATION_FORMATS.includes(format)) {
    return noData(CHECK_ATTESTATION, `this verifier does not know the format "${format}"`);
  }
  if (member(content, 'policy_public_key') !== envelope.signer_public_key) {
    return check(CHECK_ATTESTATION, FAIL, 'leaf 3 vouches for a key the envelope does not name');
  }
  if (!trust || !now) {
    return noData(
      CHECK_ATTESTATION,
      'no PCR allowlist and moment were pinned, so nothing says which enclave this is',
    );
  }
  const document = fromBase64(member(content, 'document'));
  if (document === null) return check(CHECK_ATTESTATION, FAIL, "leaf 3's document is not base64");
  let inner;
  try {
    inner = await verifyAttestation(document, {
      trust,
      now,
      expectedPublicKey: fromHex(envelope.signer_public_key),
      expectedUserData: fromHex(envelope.policy_hash),
    });
  } catch (e) {
    return check(CHECK_ATTESTATION, FAIL, String(e && e.message ? e.message : e));
  }
  if (inner.failures.length) {
    return check(CHECK_ATTESTATION, FAIL, inner.failures.map((c) => `${c.name}: ${c.detail}`).join('; '));
  }
  if (inner.deferred.length) {
    return noData(CHECK_ATTESTATION, inner.deferred.map((c) => `${c.name}: ${c.detail}`).join('; '));
  }
  return outcome(
    CHECK_ATTESTATION,
    true,
    'an attested enclave matching the pinned measurements held this policy key',
  );
}

function decimalEqual(a, b) {
  // Amounts are decimal strings, never floats. Compare by normalizing the
  // scale rather than by parsing to a double, which is how "250.00" and
  // "250.000" end up disagreeing with themselves.
  const norm = (s) => {
    const m = /^([+-]?)(\d*)(?:\.(\d*))?$/.exec(String(s).trim());
    if (!m) return null;
    const sign = m[1] === '-' ? '-' : '';
    const whole = (m[2] || '0').replace(/^0+(?=\d)/, '');
    const frac = (m[3] || '').replace(/0+$/, '');
    const body = frac ? `${whole}.${frac}` : whole;
    return body === '0' ? '0' : sign + body;
  };
  return norm(a) !== null && norm(a) === norm(b);
}

function decimalSum(values) {
  // Fixed-point addition over the two decimal scales receipts use.
  let scale = 0;
  for (const v of values) {
    const dot = String(v).indexOf('.');
    if (dot >= 0) scale = Math.max(scale, String(v).length - dot - 1);
  }
  let total = 0n;
  for (const v of values) {
    const s = String(v).trim();
    const negative = s.startsWith('-');
    const body = negative ? s.slice(1) : s;
    const [whole, frac = ''] = body.split('.');
    const scaled = BigInt(whole + frac.padEnd(scale, '0'));
    total += negative ? -scaled : scaled;
  }
  const negative = total < 0n;
  const digits = (negative ? -total : total).toString().padStart(scale + 1, '0');
  const out = scale
    ? `${digits.slice(0, digits.length - scale)}.${digits.slice(digits.length - scale)}`
    : digits;
  return (negative ? '-' : '') + out;
}

function currencyKey(currency) {
  if (typeof currency === 'string') return currency;
  if (currency && typeof currency === 'object') return `${currency.code}.${currency.issuer}`;
  return '?';
}

function intentMatchesCheck(intent, settlement, settled) {
  const name = CHECK_INTENT_MATCHES;
  if (settlement === null) {
    return noData(name, 'nothing settled, so there are no settled fields to compare');
  }
  if (intent === null) return check(name, FAIL, 'the intent leaf does not parse');
  const deltas = member(settled, 'balance_deltas');
  if (!Array.isArray(deltas) || !deltas.length) {
    return noData(name, 'the receipt records no balance deltas to compare the intent to');
  }
  const amount = member(intent, 'amount');
  const wanted = currencyKey(member(amount, 'currency'));
  const destination = member(intent, 'destination');
  const treasury = member(intent, 'treasury');
  const credited = deltas.filter(
    (d) => d.account === destination && currencyKey(d.currency) === wanted,
  );
  if (!credited.length) {
    return check(name, FAIL, `no balance delta credits ${destination} in the intent's currency`);
  }
  const total = decimalSum(credited.map((d) => d.value));
  if (!decimalEqual(total, amount.value)) {
    return check(name, FAIL, `${destination} received ${total}, the intent asked for ${amount.value}`);
  }
  const debited = deltas.filter((d) => d.account === treasury && currencyKey(d.currency) === wanted);
  if (debited.length) {
    const paid = decimalSum(debited.map((d) => d.value));
    if (!decimalEqual(paid, `-${amount.value}`)) {
      return check(name, FAIL, `${treasury} paid ${paid}, the intent asked for -${amount.value}`);
    }
  }
  return outcome(name, true, `${destination} received ${amount.value}`);
}

function anchorCheck(settlement, envelope) {
  const name = CHECK_ANCHOR;
  if (settlement === null) return noData(name, 'nothing settled, so there is no anchor to compare');
  const observed = member(settlement, 'observed_anchor');
  if (!observed) {
    return noData(name, 'the settlement leaf records no anchor read back from the rail');
  }
  return outcome(
    name,
    String(observed).toLowerCase() === String(envelope.left).toLowerCase(),
    `the rail carried ${String(observed).toLowerCase()}, LEFT is ${envelope.left}`,
  );
}

async function signedBlobCheck(settlement) {
  const name = CHECK_SIGNED_BLOB;
  if (settlement === null) return noData(name, 'nothing settled, so there is no signed blob');
  const blob = member(settlement, 'signed_tx_blob');
  if (!blob) return noData(name, 'the settlement leaf carries no signed transaction blob');
  const derived = await txIdFromBlob(member(settlement, 'rail'), blob);
  if (derived === null) {
    return noData(name, `this verifier has no transaction-id rule for rail "${member(settlement, 'rail')}"`);
  }
  const claimed = String(member(settlement, 'tx_hash') ?? '');
  return outcome(
    name,
    derived.toLowerCase() === claimed.toLowerCase(),
    `the blob hashes to ${derived}, the receipt names ${claimed}`,
  );
}

// -- the checks that need material the verifier brought --------------------

async function policyDocumentCheck(envelope, supplied, adminPublicKey) {
  if (supplied === null || supplied === undefined) {
    return [
      noData(
        CHECK_POLICY_DOCUMENT,
        'no policy document was supplied, so the rules that ran cannot be re-read',
      ),
      null,
    ];
  }
  const signed = member(supplied, 'document') ? supplied : null;
  const document = signed ? signed.document : supplied;
  let note = '';
  if (signed) {
    if (adminPublicKey) {
      if (signed.signer_public_key !== adminPublicKey) {
        return [check(CHECK_POLICY_DOCUMENT, FAIL, 'the policy is signed by another key'), document];
      }
      // Covers both signature shapes (legacy Ed25519 over the pre-image, or an
      // ApprovalAssertion — Ed25519 or WebAuthn — over policy_hash): one
      // verification path for either kind of admin.
      const outcome = await policySignatureOutcome(signed, {
        credential_type: 'ed25519',
        public_key: adminPublicKey,
      });
      if (outcome === null) {
        return [
          noData(
            CHECK_POLICY_DOCUMENT,
            'this runtime has no Ed25519 in Web Crypto, so the policy signature is unchecked',
          ),
          document,
        ];
      }
      if (!outcome) {
        return [
          check(CHECK_POLICY_DOCUMENT, FAIL, "the policy document's admin signature does not verify"),
          document,
        ];
      }
      note = ' and the pinned admin key signed it';
    } else {
      note = '; no admin key was pinned, so who authorized these rules is unchecked';
    }
  } else {
    note = '; this document carries no signature to check';
  }
  const derived = await policyHash(document);
  if (derived !== envelope.policy_hash) {
    return [
      check(
        CHECK_POLICY_DOCUMENT,
        FAIL,
        `the supplied policy hashes to ${derived}, the receipt names ${envelope.policy_hash}`,
      ),
      document,
    ];
  }
  return [
    outcome(
      CHECK_POLICY_DOCUMENT,
      true,
      `the supplied policy hashes to the ${envelope.policy_hash.slice(0, 16)}… the decision ` +
        `names${note}`,
    ),
    document,
  ];
}

async function escalationChallengeCheck(contents, escalation) {
  if (!escalation) {
    return noData(CHECK_ESCALATION_CHALLENGE, 'this decision did not escalate, so nothing was signed');
  }
  const derived = await escalationChallenge(contents);
  if (derived === null) {
    return check(CHECK_ESCALATION_CHALLENGE, FAIL, 'LEFT_pre does not compute');
  }
  return outcome(
    CHECK_ESCALATION_CHALLENGE,
    derived === String(escalation.challenge).toLowerCase(),
    `LEFT_pre over these leaves is ${derived}, the escalation names ${escalation.challenge}`,
  );
}

async function approvalQuorumCheck(escalation, challengeOk, policy) {
  if (!escalation) {
    return [noData(CHECK_APPROVAL_QUORUM, 'this decision did not escalate, so nobody approved'), []];
  }
  if (!policy) {
    return [
      noData(
        CHECK_APPROVAL_QUORUM,
        'no policy document was supplied, so nothing says whose signature counts',
      ),
      [],
    ];
  }
  if (!challengeOk) {
    return [
      check(
        CHECK_APPROVAL_QUORUM,
        FAIL,
        'the challenge is not LEFT_pre, so the approvals are over another payment',
      ),
      [],
    ];
  }
  const challenge = fromHex(escalation.challenge);
  const quorum = await verifyQuorum(
    escalation.approvals ?? [],
    challenge,
    policy.approvers ?? [],
    escalation.quorum,
  );
  const rejected = quorum.checks.filter((c) => !c.valid);
  let detail = `${quorum.accepted.length} of ${escalation.quorum} required approvals verify`;
  if (rejected.length) {
    detail += `; rejected: ${rejected.map((c) => c.detail).join('; ').slice(0, 160)}`;
  }
  return [outcome(CHECK_APPROVAL_QUORUM, quorum.reached, detail), quorum.accepted];
}

async function logJoinCheck(envelope, bundle, log) {
  if (!bundle) {
    return noData(CHECK_LOG_JOIN, 'no session bundle was supplied, so this is a level-1 verdict');
  }
  const locator = envelope.session_locator;
  if (!locator) {
    return noData(CHECK_LOG_JOIN, 'this receipt names no session, so there is nothing to join it to');
  }
  const rows = Array.isArray(bundle.actions) ? bundle.actions : [];
  const sessionId = bundle.session ? String(bundle.session.session_id ?? '') : '';
  if (sessionId && sessionId !== locator.session_id) {
    return check(
      CHECK_LOG_JOIN,
      FAIL,
      `the receipt names session ${locator.session_id}, the bundle is ${sessionId}`,
    );
  }
  if (locator.leaf_index >= rows.length) {
    return check(
      CHECK_LOG_JOIN,
      FAIL,
      `the receipt names leaf ${locator.leaf_index}, the bundle has ${rows.length} actions`,
    );
  }
  const committed = String(rows[locator.leaf_index].input_hash ?? '');
  const derived = await canonicalHashHex(envelope);
  if (derived !== committed) {
    return check(
      CHECK_LOG_JOIN,
      FAIL,
      `the envelope hashes to ${derived}, action ${locator.leaf_index} committed ${committed}`,
    );
  }
  const actionOk = log.actions.some((a) => a.index === locator.leaf_index && a.ok);
  return outcome(
    CHECK_LOG_JOIN,
    actionOk,
    `the envelope hash is action ${locator.leaf_index} of session ${locator.session_id}, ` +
      (actionOk
        ? 'and that action proves into the session root'
        : 'but that action does not prove into the session root'),
  );
}

// -- plain language --------------------------------------------------------

const SOURCE_WORDS = {
  human_input: 'a person typed it',
  mandate: 'a standing mandate authorized it',
  system: 'a system triggered it',
};

function amountWords(intent) {
  const amount = member(intent, 'amount');
  const value = member(amount, 'value') || '?';
  const currency = member(amount, 'currency');
  let code = '?';
  if (typeof currency === 'string') code = currency;
  else if (currency && typeof currency === 'object') code = String(currency.code ?? '?');
  return `${value} ${code}`;
}

/**
 * The five sentences a non-technical reader needs, before any hash.
 *
 * Every member is a sentence or `null`. `null` means the receipt does not say,
 * and the page prints that rather than an empty line, because a blank line reads
 * as "nothing to report" and absence is a finding.
 */
export function summarize(contents, envelope, approvedIds = []) {
  const instruction = contentAt(contents, 0);
  const intent = contentAt(contents, 1);
  const decision = contentAt(contents, 2);
  const attestation = contentAt(contents, 3);
  const settlement = contentAt(contents, 4);
  const settled = contentAt(contents, 5);
  const reasoning = contentAt(contents, 6);

  const source = String(member(instruction, 'source') ?? '');
  const ref = member(instruction, 'ref');
  let instructed = null;
  if (source) {
    const words = SOURCE_WORDS[source] ?? `the instruction came from ${source}`;
    instructed = `The agent was told to make this payment — ${words}.`;
    if (ref) instructed += ` It traces back to ${ref}.`;
  }

  let rule = null;
  if (decision && typeof decision === 'object') {
    const outcomeWord = String(decision.outcome ?? '?');
    const tier = String(decision.tier ?? '?');
    const rules = Array.isArray(decision.rules) ? decision.rules : [];
    const names = rules.filter((r) => r && typeof r === 'object');
    const blocked = names.filter((r) => r.outcome !== 'pass' && r.outcome !== null && r.outcome !== undefined);
    if (outcomeWord === 'allow') {
      rule = `The policy allowed it at the ${tier} tier; ${names.length} rules ran and all of them passed.`;
    } else if (outcomeWord === 'deny') {
      rule =
        `The policy refused it at the ${tier} tier` +
        (blocked.length ? ` — ${blocked.map((r) => String(r.name)).join(', ')} blocked it.` : '.');
    } else {
      rule = `The policy escalated it at the ${tier} tier: it needed a person.`;
    }
  }

  let approved = null;
  const escalation = member(decision, 'escalation');
  if (escalation && typeof escalation === 'object') {
    if (approvedIds.length) {
      approved =
        `${approvedIds.length} of ${escalation.quorum} required approvers signed it: ` +
        `${approvedIds.join(', ')}.`;
    } else {
      approved =
        `It needed ${escalation.quorum} approver(s); no approval in this receipt verifies ` +
        'against a policy this verifier was given.';
    }
  } else if (member(decision, 'outcome') === 'allow') {
    approved = 'No person was asked: the policy allowed it outright.';
  }

  let settledLine = null;
  if (settlement && typeof settlement === 'object') {
    const destination = member(intent, 'destination') || '?';
    settledLine =
      `${amountWords(intent)} went to ${destination} on ${settlement.rail ?? envelope.rail}, ` +
      `transaction ${String(settlement.tx_hash ?? '').slice(0, 16)}…`;
  } else if (member(settled, 'outcome') === 'denied') {
    settledLine = 'Nothing settled. The refusal is what this receipt records.';
  }

  let when = null;
  const closeTime = member(settlement, 'close_time');
  const expiresAt = member(intent, 'expires_at');
  if (typeof closeTime === 'string') when = `The ledger closed it at ${closeTime}.`;
  else if (typeof expiresAt === 'string') when = `The intent was valid until ${expiresAt}.`;

  const signer =
    attestation === null || attestation === undefined
      ? 'The signer is unattested: leaf 3 is null, so nothing proves which machine held the policy key.'
      : 'The signer published an enclave attestation for its policy key.';

  const testimony =
    reasoning && typeof reasoning === 'object'
      ? "The receipt also commits to a hash of the model's reasoning. That is testimony, " +
        'not proof: it shows the account was not edited afterwards, never that it was true.'
      : null;

  return { instructed, rule, approved, settled: settledLine, when, signer, testimony };
}

// ─── 14. the bundle: session, log, evidence ────────────────────────────────

export const CHECK_ACTIONS = 'log.actions';
export const CHECK_SESSION_ROOT = 'log.session_root';
export const CHECK_CONTINUATION = 'log.continuation';
export const CHECK_AUDIT_ENTRY = 'log.audit_entry';
export const CHECK_LOG_INCLUSION = 'log.inclusion';
export const CHECK_CHECKPOINT_BODY = 'log.checkpoint_body';
export const CHECK_CHECKPOINT_SIGNATURE = 'log.checkpoint_signature';
export const CHECK_EVIDENCE = 'log.evidence';

async function readAction(index, action, sessionRoot) {
  let computed = '';
  try {
    computed = await actionLeafHash(action);
  } catch {
    computed = '';
  }
  const committed = String(action.leaf_hash ?? '');
  const proof = action.proof;
  let derived = '';
  let proofOk = false;
  if (proof && typeof proof === 'object' && committed) {
    const landed = await deriveRoot(committed, proof.siblings, proof.directions);
    if (landed !== null) {
      derived = landed;
      proofOk = derived === String(proof.root ?? sessionRoot);
    }
  }
  return {
    index,
    action_id: String(action.action_id ?? ''),
    tool_name: String(action.tool_name ?? ''),
    computed_leaf: computed,
    committed_leaf: committed,
    leaf_matches: Boolean(computed) && computed === committed,
    proof_ok: proofOk,
    derived_root: derived,
    receipt_id: action.receipt_id ?? null,
    get ok() {
      return this.leaf_matches && this.proof_ok;
    },
  };
}

/** Re-hash each disclosed evidence record against the leaf the bundle committed. */
export async function verifyEvidence(records, actions) {
  const byId = new Map(actions.map((a, i) => [String(a.action_id ?? ''), [i, a]]));
  const readings = [];
  for (const record of records ?? []) {
    if (!record || typeof record !== 'object' || Array.isArray(record)) {
      readings.push({ action_id: '', label: '(unparseable line)', verdict: 'bad', detail: 'not valid JSON', index: null });
      continue;
    }
    const actionId = String(record.action_id ?? '');
    const hit = byId.get(actionId);
    if (!hit) {
      readings.push({
        action_id: actionId,
        label: actionId || '(no action_id)',
        verdict: 'unknown',
        detail: 'no such action in this bundle',
        index: null,
      });
      continue;
    }
    const [index, action] = hit;
    const inputOk = (await canonicalHashHex(record.input ?? null)) === String(action.input_hash ?? '');
    const outputOk = (await canonicalHashHex(record.output ?? null)) === String(action.output_hash ?? '');
    const label = `${action.tool_name ?? '?'} · ${actionId.slice(0, 8)}`;
    if (inputOk && outputOk) {
      readings.push({
        action_id: actionId,
        label,
        verdict: 'ok',
        detail: 'input and output match the committed hashes',
        index,
      });
    } else {
      const detail = [
        inputOk ? '' : 'INPUT hash mismatch — record altered or fabricated.',
        outputOk ? '' : 'OUTPUT hash mismatch — record altered or fabricated.',
      ]
        .filter(Boolean)
        .join(' ');
      readings.push({ action_id: actionId, label, verdict: 'bad', detail, index });
    }
  }
  return readings;
}

/** Parse a JSONL evidence file. Unparseable lines become `null`, never skipped. */
export function evidenceRecords(text) {
  const out = [];
  for (const line of String(text).split('\n')) {
    if (!line.trim()) continue;
    try {
      out.push(JSON.parse(line));
    } catch {
      out.push(null);
    }
  }
  return out;
}

/**
 * Verify a v1.1 or v1.2 proof bundle's session, log and checkpoint claims.
 *
 * A bundle with no transparency block is not failing — it is a level-1 export,
 * and the checks that need a log report `not_implemented` by name. That is plan
 * D9 in one function.
 */
export async function verifyLogBundle(bundle, { evidence = [] } = {}) {
  const session = bundle.session && typeof bundle.session === 'object' ? bundle.session : null;
  const root = session ? String(session.root_hash ?? '') : '';
  const actions = Array.isArray(bundle.actions)
    ? bundle.actions.filter((a) => a && typeof a === 'object')
    : [];

  const readings = [];
  for (let i = 0; i < actions.length; i++) readings.push(await readAction(i, actions[i], root));

  const checks = [];
  if (!actions.length) {
    checks.push(noData(CHECK_ACTIONS, 'this bundle carries no actions'));
  } else {
    const good = readings.filter((r) => r.ok).length;
    checks.push(
      outcome(
        CHECK_ACTIONS,
        good === readings.length,
        `${good} of ${readings.length} actions rehash to their leaf and prove into the root`,
      ),
    );
  }

  if (!root) {
    checks.push(noData(CHECK_SESSION_ROOT, 'the bundle states no session root'));
  } else {
    const roots = [...new Set(readings.filter((r) => r.proof_ok).map((r) => r.derived_root))];
    const agrees = roots.length === 1 && roots[0] === root;
    checks.push(
      outcome(
        CHECK_SESSION_ROOT,
        agrees,
        agrees
          ? `every verified proof lands on ${root}`
          : `proofs land on ${JSON.stringify(roots.sort())}, the session states ${root}`,
      ),
    );
  }

  const continuation = bundle.continuation;
  if (continuation && typeof continuation === 'object') {
    const computed = await bindingLeafHash(
      String(continuation.parent_session_id),
      String(continuation.parent_root),
      String(continuation.reason),
    );
    const committed = String(continuation.binding_leaf_hash ?? '');
    if (computed === null) {
      checks.push(check(CHECK_CONTINUATION, FAIL, 'the binding does not hash'));
    } else if (computed !== committed) {
      checks.push(
        check(
          CHECK_CONTINUATION,
          FAIL,
          `the binding recomputes to ${computed}, the bundle commits ${committed}`,
        ),
      );
    } else if (!continuation.proof || typeof continuation.proof !== 'object') {
      checks.push(noData(CHECK_CONTINUATION, 'the bundle carries no proof for the binding leaf'));
    } else {
      const derived = await deriveRoot(
        committed,
        continuation.proof.siblings,
        continuation.proof.directions,
      );
      const proofRoot = String(continuation.proof.root ?? '');
      checks.push(
        outcome(
          CHECK_CONTINUATION,
          derived === proofRoot,
          `the binding leaf folds to ${derived}, the successor root is ${proofRoot}`,
        ),
      );
    }
  } else {
    checks.push(noData(CHECK_CONTINUATION, 'this session did not continue another one'));
  }

  const audit = bundle.audit_log;
  if (audit && typeof audit === 'object') {
    const computed = await auditEntryHash(audit);
    const committed = String(audit.current_hash ?? '');
    checks.push(
      computed === null
        ? check(CHECK_AUDIT_ENTRY, FAIL, 'the entry does not hash')
        : outcome(
            CHECK_AUDIT_ENTRY,
            computed === committed,
            `the entry recomputes to ${computed}, the bundle records ${committed}`,
          ),
    );
  } else {
    checks.push(noData(CHECK_AUDIT_ENTRY, 'this bundle carries no audit-log entry'));
  }

  const transparency =
    bundle.transparency && typeof bundle.transparency === 'object' ? bundle.transparency : {};
  const inclusion = transparency.log_inclusion;
  if (inclusion && typeof inclusion === 'object') {
    const read = await verifyLogInclusion(inclusion);
    checks.push(outcome(CHECK_LOG_INCLUSION, read.ok, read.detail));
  } else {
    checks.push(noData(CHECK_LOG_INCLUSION, 'this bundle carries no log inclusion proof'));
  }

  const checkpoint = transparency.checkpoint;
  if (checkpoint && typeof checkpoint === 'object') {
    const body = checkpointBodyMatches(checkpoint);
    checks.push(outcome(CHECK_CHECKPOINT_BODY, body.ok, body.detail));
    const key = checkpoint.public_key;
    const signature = checkpoint.signature;
    if (typeof checkpoint.body !== 'string' || typeof key !== 'string' || typeof signature !== 'string') {
      checks.push(noData(CHECK_CHECKPOINT_SIGNATURE, 'the checkpoint carries no body, key or signature'));
    } else {
      const ok = await ed25519Verify(key, signature, utf8(checkpoint.body));
      checks.push(
        ok === null
          ? noData(
              CHECK_CHECKPOINT_SIGNATURE,
              'this runtime has no Ed25519 in Web Crypto — verify the body and signature ' +
                'with any external Ed25519 tool',
            )
          : outcome(
              CHECK_CHECKPOINT_SIGNATURE,
              ok,
              `key ${key.slice(0, 16)}… ${ok ? 'signed' : 'did not sign'} this checkpoint body`,
            ),
      );
    }
  } else {
    checks.push(noData(CHECK_CHECKPOINT_BODY, 'this bundle carries no checkpoint'));
    checks.push(noData(CHECK_CHECKPOINT_SIGNATURE, 'this bundle carries no checkpoint'));
  }

  const evidenceReadings = await verifyEvidence(evidence, actions);
  if (evidenceReadings.length) {
    const bad = evidenceReadings.filter((e) => e.verdict === 'bad').length;
    const good = evidenceReadings.filter((e) => e.verdict === 'ok').length;
    checks.push(
      outcome(
        CHECK_EVIDENCE,
        bad === 0 && good > 0,
        `${good} record(s) match their committed hashes, ${bad} do not`,
      ),
    );
  }

  return { result: result(checks), actions: readings, evidence: evidenceReadings };
}

// -- the whole receipt -----------------------------------------------------

function authorizationLine(res, settled) {
  const signature = res.get(CHECK_POLICY_SIGNATURE);
  const blob = res.get(CHECK_SIGNED_BLOB);
  if (!settled) return [AUTHORIZATION_ABSENT, 'nothing settled, so no transaction was authorized'];
  if (!signature || signature.status === NOT_IMPLEMENTED) {
    return [AUTHORIZATION_ABSENT, signature ? signature.detail : 'no policy signature was checked'];
  }
  if (signature.status === FAIL) return [AUTHORIZATION_CONTRADICTED, signature.detail];
  if (blob && blob.status === FAIL) return [AUTHORIZATION_CONTRADICTED, blob.detail];
  if (blob && blob.status === PASS) {
    return [
      AUTHORIZATION_VERIFIED,
      'the policy key signed a payload carrying LEFT, and the transaction id ' +
        're-derives from the blob that was submitted',
    ];
  }
  return [
    AUTHORIZATION_VERIFIED,
    'the policy key signed a payload carrying LEFT; the blob itself was not supplied',
  ];
}

/**
 * Verify a receipt as far as the supplied material allows, and say how far.
 *
 * `receipt` is a v1.2 `receipts[]` entry: `{envelope, leaves}`. Everything in
 * `options` is something the *verifier* brought — the PCR allowlist and the
 * moment to judge it at, the validator key set, the policy document and the
 * admin key that signed it, the session bundle to join. Each one absent turns
 * its checks into named `not_implemented` entries: never a pass, never silence.
 *
 * Returns the same shape `merkl.core.verify.receipt.ReceiptVerdict.to_content()`
 * produces, so the two implementations are compared object to object.
 */
export async function verifyReceipt(receipt, options = {}) {
  const {
    attestationTrust = null,
    now = null,
    validatorTrust = null,
    settlementProof = null,
    policyDocument = null,
    adminPublicKey = null,
    sessionBundle = null,
    liveSettlement = false,
  } = options;

  const envelope = receipt.envelope ?? {};
  const contents = Array.isArray(receipt.leaves) ? receipt.leaves : [];
  const committed = envelope.leaf_hashes ?? [];

  const checks = [];
  checks.push(
    outcome(CHECK_VERSION, envelope.version === RECEIPT_VERSION, `version "${envelope.version}"`),
  );
  checks.push(outcome(CHECK_LEAF_COUNT, contents.length === 7, `${contents.length} leaf contents`));
  checks.push(
    outcome(
      CHECK_REQUIRED_LEAVES,
      REQUIRED_LEAVES.every((n) => {
        const i = LEAF_NAMES.indexOf(n);
        return i < contents.length && contents[i] !== null && contents[i] !== undefined;
      }),
      `${JSON.stringify(REQUIRED_LEAVES)} are present in every receipt`,
    ),
  );

  const { checks: leaves, computed } = await leafChecks(envelope, contents);
  checks.push(...leaves);
  checks.push(outcome(CHECK_PADDING, committed[7] === committed[6], 'leaf 7 must repeat leaf 6'));

  let committedLeft = null;
  try {
    committedLeft = await buildLeft(committed);
  } catch {
    committedLeft = null;
  }
  const head = computed.slice(0, 4);
  if (head.some((h) => h === null) || committedLeft === null) {
    checks.push(check(CHECK_LEFT, FAIL, 'LEFT cannot be recomputed: a leaf in 0-3 does not hash'));
  } else {
    const recomputed = await buildLeft(head);
    checks.push(
      outcome(
        CHECK_LEFT,
        committedLeft === envelope.left && recomputed === envelope.left,
        `LEFT over leaves 0-3 is ${committedLeft}`,
      ),
    );
  }

  const settlement = contentAt(contents, 4);
  const settledResult = contentAt(contents, 5);
  const intent = contentAt(contents, 1);
  const decision = contentAt(contents, 2);
  const escalation = member(decision, 'escalation');

  const [documentCheck, policy] = await policyDocumentCheck(envelope, policyDocument, adminPublicKey);
  const challengeCheck = await escalationChallengeCheck(contents, escalation);
  const [quorumCheck, approvedIds] = await approvalQuorumCheck(
    escalation,
    challengeCheck.status === PASS,
    policy,
  );
  checks.push(documentCheck, challengeCheck, quorumCheck);

  const early = policySignatureCheck(settlement, envelope);
  checks.push(early !== null ? early : await finishPolicySignature(settlement, envelope));
  checks.push(await attestationCheck(contentAt(contents, 3), envelope, attestationTrust, now));
  checks.push(intentMatchesCheck(intent, settlement, settledResult));
  checks.push(anchorCheck(settlement, envelope));
  checks.push(await signedBlobCheck(settlement));

  let reading;
  if (settlement === null || settlement === undefined) {
    reading = {
      checks: [
        noData(CHECK_PROOF_MATCHES, 'nothing settled, so there is no proof to read'),
        noData(CHECK_LEDGER_HEADER, 'nothing settled, so there is no ledger to check'),
        noData(CHECK_VALIDATOR_QUORUM, 'nothing settled, so no validators signed anything'),
      ],
      ledger_inclusion: LEDGER_UNCHECKED,
      detail: 'nothing settled, so there is no ledger inclusion to establish',
    };
  } else {
    reading = await readSettlementProof(settlementProof, {
      rail: settlement.rail,
      txHash: settlement.tx_hash,
      ledgerIndex: settlement.ledger_index,
      trust: validatorTrust,
      live: liveSettlement,
    });
  }
  checks.push(...reading.checks);
  const inclusionStatus =
    reading.ledger_inclusion === LEDGER_PROVEN_OFFLINE ||
    reading.ledger_inclusion === LEDGER_VERIFIED_LIVE
      ? PASS
      : reading.checks.some((c) => c.status === FAIL)
        ? FAIL
        : NOT_IMPLEMENTED;
  checks.push(
    check(CHECK_LEDGER_INCLUSION, inclusionStatus, `${reading.ledger_inclusion}: ${reading.detail}`),
  );

  let committedRight = null;
  try {
    committedRight = await buildRight(committed);
  } catch {
    committedRight = null;
  }
  const tail = computed.slice(4, 7);
  if (tail.some((h) => h === null) || committedRight === null) {
    checks.push(check(CHECK_RIGHT, FAIL, 'RIGHT cannot be recomputed: a leaf in 4-6 does not hash'));
  } else {
    const recomputed = await buildRight([...committed.slice(0, 4), ...tail, tail[2]]);
    checks.push(
      outcome(CHECK_RIGHT, recomputed === committedRight, `RIGHT over leaves 4-7 is ${committedRight}`),
    );
  }

  let recomputedRoot = null;
  if (committedLeft !== null && committedRight !== null) {
    recomputedRoot = await buildRoot(committedLeft, committedRight);
  }
  checks.push(
    outcome(
      CHECK_ROOT,
      recomputedRoot === envelope.root,
      `SHA-256(LEFT || RIGHT) is ${recomputedRoot}`,
    ),
  );

  checks.push(
    outcome(CHECK_ENVELOPE_RAIL, member(intent, 'rail') === envelope.rail, `envelope rail "${envelope.rail}"`),
  );
  checks.push(
    outcome(
      CHECK_ENVELOPE_TREASURY,
      member(intent, 'treasury') === envelope.treasury,
      `envelope treasury "${envelope.treasury}"`,
    ),
  );
  checks.push(
    outcome(
      CHECK_ENVELOPE_POLICY_HASH,
      member(decision, 'policy_hash') === envelope.policy_hash,
      `envelope policy_hash ${envelope.policy_hash}`,
    ),
  );

  let log = null;
  if (sessionBundle) log = await verifyLogBundle(sessionBundle);
  const join = await logJoinCheck(envelope, sessionBundle, log ?? { actions: [] });
  checks.push(join);

  const res = result(checks);
  const [authorization, authorizationDetail] = authorizationLine(res, settlement !== null && settlement !== undefined);
  const level = join.status === PASS ? LEVEL_SESSION : LEVEL_RECEIPT;
  const attestationResult = res.get(CHECK_ATTESTATION);
  const leafThree = contentAt(contents, 3);
  const attested =
    leafThree === null || leafThree === undefined
      ? false
      : attestationResult && attestationResult.status === PASS
        ? true
        : null;

  return {
    receipt_id: envelope.receipt_id,
    ok: res.ok && (log ? log.result.ok : true),
    complete: res.complete && (log ? log.result.complete : true),
    level,
    level_detail:
      level === LEVEL_SESSION
        ? 'level 2: this receipt is committed in a session log whose checkpoint and ' +
          'inclusion proof were checked here'
        : 'level 1: verified against the signer key, the rail and this receipt alone — ' +
          'joining a session log would add completeness, a notary signature and an anchor',
    settlement: {
      transaction_authorization: authorization,
      transaction_authorization_detail: authorizationDetail,
      ledger_inclusion: reading.ledger_inclusion,
      ledger_inclusion_detail: reading.detail,
    },
    attested,
    summary: summarize(contents, envelope, approvedIds),
    checks: res.checks,
    log: log
      ? {
          ok: log.result.ok,
          complete: log.result.complete,
          checks: log.result.checks.map((c) => ({ name: c.name, status: c.status })),
          actions: log.actions.map((a) => ({ ...a, ok: a.ok })),
          evidence: log.evidence,
        }
      : undefined,
    result: res,
  };
}

/**
 * The one call a page makes: verify a whole bundle, receipts included.
 *
 * Accepts a session bundle (v1.1 or v1.2) or a receipt-only bundle
 * (`{version, receipts:[…], session: null}`) — the two shapes merkl-api renders
 * and `merkl disclose` writes. Returns `{log, receipts, ok, complete}`; the page
 * renders words out of that and computes nothing of its own.
 */
export async function verifyBundle(bundle, options = {}) {
  const { evidence = [], receiptOptions = {} } = options;
  const hasSession = Boolean(bundle && bundle.session);
  const log = hasSession ? await verifyLogBundle(bundle, { evidence }) : null;
  const receipts = [];
  for (const entry of bundle?.receipts ?? []) {
    if (!entry || typeof entry !== 'object') continue;
    receipts.push(
      await verifyReceipt(entry, {
        settlementProof: entry.settlement_proof ?? null,
        policyDocument: entry.policy_document ?? null,
        sessionBundle: hasSession ? bundle : null,
        ...receiptOptions,
      }),
    );
  }
  return {
    log,
    receipts,
    ok: (log ? log.result.ok : true) && receipts.every((r) => r.ok),
    complete: (log ? log.result.complete : true) && receipts.every((r) => r.complete),
  };
}

// -- selective disclosure --------------------------------------------------

export const CHECK_DISCLOSURE_ROOT = 'disclosure.root';

/**
 * Check a disclosure against a root the reader already trusts.
 *
 * The root is an input, not something the disclosure gets to assert: it comes
 * from the envelope, from the session log, or from wherever the reader pinned
 * it. A disclosure that supplied its own root would verify against itself.
 */
export async function verifyDisclosure(disclosure, root) {
  const leafHashes = disclosure.leaf_hashes ?? [];
  const checks = [
    outcome(CHECK_VERSION, disclosure.version === RECEIPT_VERSION, `version is "${disclosure.version}"`),
    outcome(
      CHECK_DISCLOSURE_ROOT,
      disclosure.root === root,
      `disclosure root ${disclosure.root} vs expected ${root}`,
    ),
    outcome(CHECK_LEAF_COUNT, leafHashes.length === 8, `${leafHashes.length} leaf hashes`),
    outcome(CHECK_PADDING, leafHashes[7] === leafHashes[6], 'leaf 7 must repeat leaf 6'),
  ];
  for (const leaf of disclosure.leaves ?? []) {
    let computed = null;
    try {
      computed = await receiptLeafHash(leaf.name, leaf.content);
    } catch (e) {
      checks.push(check(`leaf.${leaf.name}`, FAIL, String(e)));
      checks.push(check(`proof.${leaf.name}`, FAIL, 'leaf hash unavailable'));
      continue;
    }
    const committed = leafHashes[leaf.index];
    checks.push(
      outcome(`leaf.${leaf.name}`, computed === committed, `recomputed ${computed} vs committed ${committed}`),
    );
    const derived = await deriveRoot(computed, leaf.proof.siblings, leaf.proof.directions);
    checks.push(outcome(`proof.${leaf.name}`, derived === root, `proof folds to ${derived}`));
  }
  const left = await buildLeft(leafHashes);
  const right = await buildRight(leafHashes);
  checks.push(outcome(CHECK_LEFT, left === disclosure.left, `recomputed LEFT ${left}`));
  const recomputedRoot = await buildRoot(left, right);
  checks.push(outcome(CHECK_ROOT, recomputedRoot === root, `recomputed ROOT ${recomputedRoot}`));
  return result(checks);
}
