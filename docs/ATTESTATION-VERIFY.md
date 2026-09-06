# Verifying an AWS Nitro attestation document

Normative for receipt check 8, `signer.attestation`. Two implementations must
agree: `merkl.core.verify.attestation` (Python, phase 3) and `@merkl/verify`
(JavaScript, phase 4). Both must reproduce every case in
`merkl/core/vectors/attestation/cases.json` — every check's *status*, not just
the overall verdict.

This document specifies bytes. Where it says "refuse", it means the check fails
and is reported by name; where it says "report `not_implemented`", it means the
inputs were absent and nothing was concluded. `not_implemented` is never a pass.

---

## 1. What leaf 3 carries

```json
{"format": "aws-nitro",
 "document": "<standard base64 of the CBOR COSE_Sign1>",
 "policy_public_key": "<lowercase hex, 32 raw Ed25519 bytes>"}
```

Frozen with `merkl-receipt-leaf-v1`. `format` is `aws-nitro`; `aws-nitro-v1` is
accepted as an alias and nothing else is (an unknown format reports
`not_implemented`, because a verifier that does not know a format has not
checked it). `document` is **standard** base64 (`+`, `/`, `=`), not base64url.

`null` at leaf 3 is a receipt that commits to having *no* attestation — an
unattested dev signer (plan D3). Report `not_implemented` naming that, never a
pass and never a silent skip.

The policy hash is not repeated in leaf 3. It is in leaf 2 and the envelope, and
it is bound into the document as `user_data`; §7 is where the three are held
together.

---

## 2. The CBOR profile

Accept exactly this subset of RFC 8949, and refuse the rest:

| Accept | Refuse |
|---|---|
| definite-length arrays, maps, byte and text strings | every indefinite length (additional info 31) |
| shortest-form integer heads | a value encoded in more bytes than it needs (`0x1817` for 23) |
| unsigned and negative integers | floats, and every simple value but `false` (0xf4), `true` (0xf5), `null` (0xf6) |
| integer and text-string map keys | byte-string or composite map keys; a repeated key |
| tag 18 (COSE_Sign1), unwrapped | every other tag |

Also bound, before allocating: nesting depth (16 is ample), the declared element
count of any array or map, and the total document length. The document arrives
from an untrusted party; a reader that trusts a length prefix can be told to
allocate anything.

A **deterministic writer** is required, not optional — §5 re-encodes an array to
check a signature over it. RFC 8949 §4.2.1: shortest-form heads, definite
lengths, map keys sorted by their encoded bytes.

Reference: `merkl/core/verify/cbor.py`, `tests/core/test_cbor.py`.

---

## 3. COSE_Sign1

The document decodes to a four-element array (RFC 9052 §4.2):

```
[ protected: bstr, unprotected: map, payload: bstr, signature: bstr ]
```

* `protected` is a byte string whose contents are a CBOR map. Decode it: key `1`
  (alg) must be `-35`, ES384. Nothing else is read from it.
* `unprotected` must be a map. Its contents are not used and must not be trusted;
  they are not covered by the signature.
* `signature` is exactly 96 bytes: `r` and `s`, 48 bytes each, big-endian, **not**
  DER. A verifier using a DER-based API must re-encode them.

Refuse anything that is not four elements, or whose `protected`, `payload` or
`signature` is not a byte string.

---

## 4. The payload

`payload` is a byte string whose contents are a CBOR map with these members:

| Member | Type | Required | Notes |
|---|---|---|---|
| `module_id` | text | yes | non-empty |
| `digest` | text | yes | must be `"SHA384"` |
| `timestamp` | uint | yes | milliseconds since the Unix epoch, positive |
| `pcrs` | map | yes | integer keys 0-31, values 32, 48 or 64 bytes. AWS emits 48 (SHA-384) |
| `certificate` | bstr | yes | the leaf certificate, DER |
| `cabundle` | array of bstr | yes | root first, then intermediates. Non-empty |
| `public_key` | bstr or null | optional | what the enclave asked to be vouched for |
| `user_data` | bstr or null | optional | what the enclave asked to be recorded |
| `nonce` | bstr or null | optional | caller-supplied freshness |

Unknown members are tolerated (they are covered by the signature and do not
change what the known ones mean). A member of the wrong type is a refusal.

---

## 5. The checks, in order

Each is reported by name with a status of `pass`, `fail` or `not_implemented`.
The names are the contract; `cases.json` records them verbatim.

### `attestation.format`

COSE alg is `-35`, `digest` is `"SHA384"`, `signature` is 96 bytes. Fail
otherwise. If the document could not be parsed at all, this check fails and every
check below reports `not_implemented` — never dropped from the list.

### `attestation.certificate_chain`

1. `cabundle[0]` must equal the DER of the pinned root, byte for byte. The root
   is **embedded in the verifier**, not taken from the document and not fetched:
   a verifier that downloads its trust anchor trusts whoever answered.
2. Build the chain `cabundle || [certificate]` — root first, leaf last.
3. For each adjacent pair, the child's issuer must equal the parent's subject,
   and the parent's public key must verify the child's signature over its
   `tbsCertificate` bytes. Every certificate in the AWS Nitro PKI is ECDSA.

The pinned root:

```
CN=aws.nitro-enclaves, OU=AWS, O=Amazon, C=US
valid  2019-10-28T13:28:05Z → 2049-10-28T14:28:05Z
DER SHA-256   641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b
published at  https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
zip SHA-256   8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c
```

The PEM is in `merkl/core/vectors/attestation/aws-nitro-root-g1.pem` and embedded
in `merkl/core/verify/attestation.py` as `NITRO_ROOT_G1_PEM`; a test asserts the
two are identical bytes. When the default anchor is in use, check its fingerprint
before trusting it — an edited embedded root is a verifier that trusts anything.

A real, correctly signed document checked against a *different* root must fail
here and pass §`attestation.signature`. That combination is the whole reason the
root is pinned, and `cases.json` has it as
`chain-does-not-reach-the-pinned-root`.

### `attestation.certificate_validity`

Every certificate in the chain must satisfy `notBefore ≤ T ≤ notAfter`, where
**T is the document's own `timestamp`**, not the verifier's `now`.

This is the check people get wrong. An NSM leaf certificate lives about three
hours. A receipt is read months or years later. Checking the chain against the
reader's clock would mean no receipt could ever be verified after the fact, which
would defeat the point of writing one down. Freshness is a *separate* question,
asked below against `now`.

### `attestation.signature`

Verify ES384 (ECDSA P-384, SHA-384) under the **leaf** certificate's public key,
over the `Sig_structure` of RFC 9052 §4.4:

```
Sig_structure = [ "Signature1", protected, external_aad, payload ]
```

`external_aad` is the empty byte string. `protected` and `payload` are the byte
strings from the COSE array, verbatim. **Re-encode this array as deterministic
CBOR** and verify over the result — do not slice bytes out of the document.

Refuse a leaf whose key is not P-384.

### `attestation.timestamp`

Let `age = now - timestamp`.

* `age < 0` fails: the document is dated after `now`.
* If the verifier pinned a `max_age_seconds`, `age > max_age_seconds` fails.
* If it pinned none (`null`), the check passes and says freshness was not asked
  for. That is the right setting for reading an old receipt, where certificate
  validity above is the meaningful bound.

### `attestation.pcrs`

For each index in the verifier's allowlist, the document's PCR at that index must
equal it, compared as bytes (or as lowercase hex; be consistent). Indices not in
the allowlist are not checked.

An **empty allowlist reports `not_implemented`**, not `pass`. A document nobody
compared to an expected measurement proves only that some enclave, somewhere,
produced it.

Typical pins: PCR0 (the image), PCR1 (kernel and bootstrap), PCR2 (the
application), PCR8 (the certificate a signed image was signed with).

### `attestation.debug_mode`

PCR0 being all zero bytes means the enclave ran in debug mode: it was never
measured and the parent could read its memory. Fail by default. A verifier may
turn this off explicitly, and then the check reports `not_implemented` saying so
— it does not silently pass.

### `attestation.public_key`

The document's `public_key` must equal the expected key, as raw bytes. For a
receipt that is `envelope.signer_public_key`, hex-decoded.

Without this check a genuine attestation from any enclave could be stapled to any
receipt. With it, the document is about *this* key.

If the caller supplied no expected key, report `not_implemented`. If the caller
supplied one and the document carries none, **fail** — the absence is the answer.

### `attestation.user_data`

The document's `user_data` must equal the expected value, as raw bytes. For a
receipt that is `envelope.policy_hash`, hex-decoded.

Same rules: no expectation supplied is `not_implemented`; an expectation with no
`user_data` in the document is a failure.

---

## 6. The two verdict lines

Never one boolean.

* `ok` — no check failed.
* `complete` — no check reported `not_implemented`.

A document can be `ok` and not `complete`, and that is a common and honest state:
a real production attestation with no `public_key` in it (like the `production`
fixture) passes everything it can and reports both bindings as unchecked.

---

## 7. Inside a receipt: check 8

`signer.attestation` runs the whole of §5 and reports one line. In order:

1. Leaf 3 is `null` → `not_implemented`, "this receipt proves it was produced by
   an unattested signer".
2. `format` is not known → `not_implemented`, naming what is known.
3. `policy_public_key` in leaf 3 ≠ `envelope.signer_public_key` → **fail**. Cheap,
   and first: leaf 3 must be about the key the envelope names before any
   cryptography is worth doing.
4. The verifier pinned no allowlist or no `now` → `not_implemented`.
5. `document` is not base64, or the envelope's hex fields are not hex → fail.
6. Run §5 with `expected_public_key = envelope.signer_public_key` and
   `expected_user_data = envelope.policy_hash`, both hex-decoded.
7. Any sub-check failed → fail, naming each. Otherwise any sub-check
   `not_implemented` → `not_implemented`, naming each. Otherwise pass.

The PCR allowlist, the root and `now` are **arguments to the verifier**, never
values read out of the receipt. No receipt gets to nominate the measurements it
should be judged against.

---

## 8. The vectors

`merkl/core/vectors/attestation/`:

| File | |
|---|---|
| `documents.json` | Three attestation documents AWS actually signed, base64, with provenance. Hand-committed. |
| `cases.json` | Seventeen verification cases, tamper cases included. Generated by `python -m merkl.core.vectors.attestation.generate`. |
| `aws-nitro-root-g1.pem` | The published root. |
| `not-the-aws-root.pem` | A throwaway P-384 certificate, so one case can pin an anchor the documents do not chain to. |

Each case gives `document_b64`, `now`, the `trust` inputs, the optional expected
key and user data, and `expect.checks` — a name-to-status map. An implementation
passes when it reproduces every status.

Every document is expired. That is the point: only a verifier that takes `now` as
an argument can check them at all, so the fixtures enforce the no-clock rule as a
side effect of existing.

The tamper cases worth reading before implementing:

| Case | What it teaches |
|---|---|
| `chain-does-not-reach-the-pinned-root` | The signature still verifies. Only the pinned root refuses it. |
| `pcr0-flipped-in-the-payload` | PCRs are inside the signed bytes, so editing one fails *two* checks. There is no quiet edit. |
| `timestamp-moved-past-the-certificate-window` | Moving the clock forward inside the document breaks certificate validity and the signature together. |
| `no-pcr-allowlist-is-not-a-pass` | Everything cryptographic passes and the PCR check still reports `not_implemented`. |
| `debug-enclave-is-refused` | A genuine, correctly signed document from an enclave whose measurements mean nothing. |

---

## 9. Notes for the JavaScript implementation

* **Signature format.** WebCrypto's `ECDSA` verify takes the raw `r ‖ s` form,
  which is what the document carries — no DER conversion needed, unlike most
  Python and Java APIs. `{name: "ECDSA", namedCurve: "P-384"}`, hash `SHA-384`.
* **Certificate parsing.** WebCrypto has no X.509 parser. Either pull in a small
  ASN.1 reader or write one for the four fields actually needed: subject, issuer,
  validity, `subjectPublicKeyInfo` — plus the `tbsCertificate` byte range, which
  must be the exact DER slice the certificate was signed over. Import the SPKI
  with `crypto.subtle.importKey("spki", …)`.
* **Time.** Take `now` as an argument, the same as Python. `verify.html` renders
  offline and its reader's clock is not evidence; a verifier that reads
  `Date.now()` cannot be checked against the fixtures.
* **Bytes, not strings.** Compare PCRs, `public_key` and `user_data` as
  `Uint8Array`s (or as lowercase hex, consistently). A case-insensitive string
  comparison somewhere in the middle is how two implementations disagree.
* **Don't reach for a CBOR package.** The profile in §2 is small, and a general
  decoder accepts shapes an attestation document may not contain — indefinite
  lengths and duplicate keys being the two that matter. The Python reader is
  about two hundred lines including its refusals.
