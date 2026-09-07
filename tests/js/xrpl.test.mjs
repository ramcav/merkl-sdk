/**
 * XRPL offline inclusion: the SHAMap fold, validations and manifests, over
 * real material — the same fixtures `tests/core/test_verify_xrpl.py` reads.
 *
 * This suite does not build a SHAMap path (only the Python adapter captures
 * one); it folds paths the committed fixtures already carry, and verifies
 * validations and manifests independently — the two things a *reader* of a
 * settlement proof actually needs to check.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  LEDGER_PROVEN_OFFLINE,
  evaluateXrplValidation,
  readSettlementProof,
  secp256k1VerifyDigest,
  xrplFoldTxPath,
} from '../../merkl/core/verify/js/merkl-verify.js';
import { xrplCases, xrplLedgerFixture } from './vectors.mjs';

const CASES = xrplCases();

test('every shamap case folds the way the fixture records', async (t) => {
  for (const c of CASES.shamap_cases) {
    await t.test(c.name, async () => {
      if ('expect_root' in c) {
        // generate.py always picks transactions[0] as the target
        const first = c.transactions[0];
        const root = await xrplFoldTxPath(c.target_tx_id, first.tx_blob, first.meta, c.expect_path);
        assert.equal(root, c.expect_root, c.description);
      } else {
        const root = await xrplFoldTxPath(
          c.target_tx_id,
          c.target_tx_blob,
          c.target_tx_meta,
          c.path,
        );
        assert.notEqual(root, c.expect_root_mismatch, c.description);
      }
    });
  }
});

test('xrplFoldTxPath is null on malformed input', () => {
  return Promise.all([
    xrplFoldTxPath('00'.repeat(32), 'aa', 'bb', [{ nibble: 16, siblings: [] }]).then((r) =>
      assert.equal(r, null),
    ),
    xrplFoldTxPath('00'.repeat(32), 'aa', 'bb', [{ nibble: 0, siblings: ['zz'] }]).then((r) =>
      assert.equal(r, null),
    ),
    xrplFoldTxPath('not-hex', 'aa', 'bb', []).then((r) => assert.equal(r, null)),
  ]);
});

test('every validation case reaches the outcome the fixture records', async (t) => {
  for (const c of CASES.validation_cases) {
    await t.test(c.name, async () => {
      const entry = { data: c.data, manifest: c.manifest };
      const verdict = await evaluateXrplValidation(entry, c.ledger_hash, c.pinned_masters);
      if (c.expect_outcome === null) {
        assert.equal(verdict, null, c.description);
      } else {
        assert.ok(verdict !== null, c.description);
        assert.equal(verdict.outcome, c.expect_outcome, c.description);
        if (c.expect_master_key !== null) {
          assert.equal(verdict.masterKey, c.expect_master_key, c.description);
        }
      }
    });
  }
});

test('a validation with no data field is unchecked', async () => {
  const verdict = await evaluateXrplValidation({}, 'ab'.repeat(32), ['ed' + '11'.repeat(32)]);
  assert.equal(verdict.outcome, 'unchecked');
});

test('a validation that does not parse is unchecked, not fatal', async () => {
  const verdict = await evaluateXrplValidation(
    { data: '00', manifest: 'x' },
    'ab'.repeat(32),
    ['ed' + '11'.repeat(32)],
  );
  assert.equal(verdict.outcome, 'unchecked');
});

test('secp256k1VerifyDigest rejects malformed input rather than throwing', () => {
  const pubkey = '02' + '11'.repeat(32);
  const digest = new Uint8Array(32);
  assert.equal(secp256k1VerifyDigest(pubkey, '00', digest), false);
  assert.equal(secp256k1VerifyDigest('00' + '11'.repeat(32), '3006020101020101', digest), false);
  assert.equal(secp256k1VerifyDigest(pubkey, '3006020101020101', digest), false);
});

test('a real testnet ledger reaches proven-offline through readSettlementProof', async () => {
  const fixture = xrplLedgerFixture('ledger_20537819.json');
  const unlCase = CASES.unl_cases.find((c) => c.name === 'testnet-unl');
  const masters = unlCase.masters;

  const proof = {
    rail: 'xrpl',
    tx_hash: fixture.tx_path.tx_hash,
    ledger_index: fixture.ledger_index,
    ledger_hash: fixture.header.ledger_hash,
    ledger_header: fixture.header,
    tx_path: {
      tx_blob: fixture.tx_path.tx_blob,
      tx_meta: fixture.tx_path.tx_meta,
      steps: fixture.tx_path.steps,
    },
    validations: fixture.validations,
    captured: [],
    missing: [],
  };
  const trust = {
    validators: Object.fromEntries(masters.map((m) => [m, m])),
    quorum: unlCase.expect_quorum,
  };
  const result = await readSettlementProof(proof, {
    rail: 'xrpl',
    txHash: proof.tx_hash,
    ledgerIndex: proof.ledger_index,
    trust,
  });
  assert.equal(result.ledger_inclusion, LEDGER_PROVEN_OFFLINE, result.detail);
  for (const c of result.checks) assert.equal(c.status, 'pass', `${c.name}: ${c.detail}`);
});

test('a tampered transaction root through readSettlementProof is not proven', async () => {
  const fixture = xrplLedgerFixture('ledger_20537819.json');
  const unlCase = CASES.unl_cases.find((c) => c.name === 'testnet-unl');
  const masters = unlCase.masters;
  const steps = fixture.tx_path.steps.map((s) => ({ ...s, siblings: [...s.siblings] }));
  steps[0].siblings[0] = 'ee'.repeat(32);

  const proof = {
    rail: 'xrpl',
    tx_hash: fixture.tx_path.tx_hash,
    ledger_index: fixture.ledger_index,
    ledger_hash: fixture.header.ledger_hash,
    ledger_header: fixture.header,
    tx_path: { tx_blob: fixture.tx_path.tx_blob, tx_meta: fixture.tx_path.tx_meta, steps },
    validations: fixture.validations,
    captured: [],
    missing: [],
  };
  const trust = {
    validators: Object.fromEntries(masters.map((m) => [m, m])),
    quorum: unlCase.expect_quorum,
  };
  const result = await readSettlementProof(proof, {
    rail: 'xrpl',
    txHash: proof.tx_hash,
    ledgerIndex: proof.ledger_index,
    trust,
  });
  assert.notEqual(result.ledger_inclusion, LEDGER_PROVEN_OFFLINE);
});
