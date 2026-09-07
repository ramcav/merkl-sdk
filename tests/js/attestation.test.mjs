/**
 * AWS Nitro attestation documents, against three AWS actually signed.
 *
 * Every fixture is expired. That is deliberate: only a verifier that takes `now`
 * as an argument can check them at all, so the fixtures enforce the no-clock rule
 * as a side effect of existing.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  NITRO_ROOT_G1_PEM,
  NITRO_ROOT_G1_SHA256,
  cborDumps,
  cborLoads,
  fromBase64,
  fromHex,
  parseAttestation,
  parseCertificate,
  pemToDer,
  sha256,
  toHex,
  verifyAttestation,
} from '../../merkl/core/verify/js/merkl-verify.js';
import { attestationCases, attestationTrust, statuses } from './vectors.mjs';

test('the embedded root is the published one, byte for byte', async () => {
  const der = pemToDer(NITRO_ROOT_G1_PEM);
  assert.equal(toHex(await sha256(der)), NITRO_ROOT_G1_SHA256);
  const cert = parseCertificate(der);
  assert.equal(cert.curve, 'P-384');
  assert.equal(toHex(cert.issuerDer), toHex(cert.subjectDer), 'a root is self-issued');
});

test('every attestation case reports the statuses the fixture records', async (t) => {
  for (const c of attestationCases().cases) {
    await t.test(c.name, async () => {
      const res = await verifyAttestation(fromBase64(c.document_b64), {
        trust: attestationTrust(c.trust, NITRO_ROOT_G1_PEM),
        now: c.now,
        expectedPublicKey: c.expected_public_key_hex ? fromHex(c.expected_public_key_hex) : null,
        expectedUserData: c.expected_user_data_hex ? fromHex(c.expected_user_data_hex) : null,
      });
      assert.deepEqual(statuses(res.checks), c.expect.checks, c.description);
      assert.equal(res.ok, c.expect.ok);
      assert.equal(res.complete, c.expect.complete);
    });
  }
});

test('the CBOR reader refuses what the profile forbids', async (t) => {
  await t.test('indefinite lengths', () => {
    assert.throws(() => cborLoads(new Uint8Array([0x9f, 0x01, 0xff])), /indefinite/);
  });
  await t.test('an integer encoded in more bytes than it needs', () => {
    assert.throws(() => cborLoads(new Uint8Array([0x18, 0x17])), /shortest form/);
  });
  await t.test('a repeated map key', () => {
    assert.throws(() => cborLoads(new Uint8Array([0xa2, 0x01, 0x01, 0x01, 0x02])), /duplicate/);
  });
  await t.test('a tag that is not COSE_Sign1', () => {
    assert.throws(() => cborLoads(new Uint8Array([0xc0, 0x01])), /tag 0 is not allowed/);
  });
  await t.test('trailing bytes after the item', () => {
    assert.throws(() => cborLoads(new Uint8Array([0x01, 0x02])), /trailing bytes/);
  });
  await t.test('a float', () => {
    assert.throws(() => cborLoads(new Uint8Array([0xfa, 0x00, 0x00, 0x00, 0x00])), /floats/);
  });
});

test('the deterministic writer round-trips the Sig_structure shape', () => {
  const encoded = cborDumps(['Signature1', new Uint8Array([1, 2]), new Uint8Array(0), new Uint8Array([3])]);
  const decoded = cborLoads(encoded);
  assert.equal(decoded[0], 'Signature1');
  assert.deepEqual(Array.from(decoded[1]), [1, 2]);
  assert.equal(decoded[2].length, 0);
  assert.deepEqual(Array.from(decoded[3]), [3]);
});

test('a document that will not parse fails format and defers the rest', async () => {
  const res = await verifyAttestation(new Uint8Array([0x00]), {
    trust: { pcrs: {} },
    now: '2022-10-13T08:58:32Z',
  });
  const s = statuses(res.checks);
  assert.equal(s['attestation.format'], 'fail');
  assert.equal(s['attestation.signature'], 'not_implemented');
  assert.equal(res.checks.length, 9, 'no check is ever dropped from the list');
});

test('the payload members a document must carry are all read', async () => {
  const c = attestationCases().cases.find((x) => x.name === 'production-enclave-fully-pinned');
  const parsed = parseAttestation(fromBase64(c.document_b64));
  assert.equal(parsed.digest, 'SHA384');
  assert.equal(parsed.signature.length, 96);
  assert.ok(parsed.pcrs.size > 0);
  assert.ok(parsed.cabundle.length > 0);
  assert.ok(parsed.timestamp > 0);
});
