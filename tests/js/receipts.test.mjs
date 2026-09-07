/**
 * Receipts: the tree, the whole verdict, and the tamper cases that must fail.
 *
 * The verdict test is the important one. It asserts that this implementation
 * reaches the same conclusion as `merkl.core.verify.receipt.verify_receipt` from
 * the *same material* — the same settlement proof, the same validator set, the
 * same policy document — down to the plain-language summary a reader sees.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  buildLeft,
  buildRight,
  buildRoot,
  canonicalHashHex,
  deriveRoot,
  escalationChallenge,
  receiptLeafHash,
  verifyDisclosure,
  verifyReceipt,
} from '../../merkl/core/verify/js/merkl-verify.js';
import { receiptVectors, tamperedVectors, verdictVectors, statuses } from './vectors.mjs';

const RECEIPTS = receiptVectors().cases;
const BY_NAME = Object.fromEntries(RECEIPTS.map((c) => [c.name, c]));

function material(m) {
  return {
    settlementProof: m.settlement_proof,
    validatorTrust: m.validator_trust,
    policyDocument: m.policy_document,
    adminPublicKey: m.admin_public_key,
    sessionBundle: m.session_bundle,
  };
}

test('every receipt hashes to the halves and root it commits', async (t) => {
  for (const c of RECEIPTS) {
    await t.test(c.name, async () => {
      for (let i = 0; i < c.leaf_names.length; i++) {
        assert.equal(await receiptLeafHash(c.leaf_names[i], c.leaves[i]), c.leaf_hashes[i]);
      }
      assert.equal(c.leaf_hashes[7], c.leaf_hashes[6], 'leaf 7 repeats leaf 6');
      assert.equal(await buildLeft(c.leaf_hashes), c.left);
      assert.equal(await buildRight(c.leaf_hashes), c.right);
      assert.equal(await buildRoot(c.left, c.right), c.root);
      assert.equal(await canonicalHashHex(c.envelope), c.envelope_hash);
    });
  }
});

test('every disclosed leaf proves into the root', async (t) => {
  for (const c of RECEIPTS) {
    await t.test(c.name, async () => {
      for (const [name, proof] of Object.entries(c.proofs)) {
        const derived = await deriveRoot(c.leaf_hashes[proof.index], proof.siblings, proof.directions);
        assert.equal(derived, c.root, `${name} does not prove into the root`);
      }
      for (const [name, proof] of Object.entries(c.half_proofs)) {
        const derived = await deriveRoot(c.leaf_hashes[proof.index], proof.siblings, proof.directions);
        assert.equal(derived, proof.subtree_root, `${name} does not prove into its half`);
      }
    });
  }
});

test('the escalation challenge recomputes from the finished receipt', async () => {
  const c = BY_NAME['escalated-approved-settled'];
  const derived = await escalationChallenge(c.leaves);
  assert.equal(derived, c.leaves[2].escalation.challenge);
});

test('the verdict agrees with the Python one, check for check', async (t) => {
  for (const c of verdictVectors().cases) {
    await t.test(c.name, async () => {
      const receipt = BY_NAME[c.name];
      const got = await verifyReceipt(
        { envelope: receipt.envelope, leaves: receipt.leaves },
        material(c.material),
      );
      assert.deepEqual(
        got.checks.map((x) => x.name),
        c.verdict.checks.map((x) => x.name),
        'the checks must run in the order the spec gives them',
      );
      assert.deepEqual(statuses(got.checks), statuses(c.verdict.checks));
      assert.equal(got.ok, c.verdict.ok);
      assert.equal(got.complete, c.verdict.complete);
      assert.equal(got.level, c.verdict.level);
      assert.equal(got.level_detail, c.verdict.level_detail);
      assert.equal(got.attested, c.verdict.attested);
      assert.deepEqual(got.settlement, c.verdict.settlement, 'plan D10 is two lines, both of them');
      assert.deepEqual(got.summary, c.verdict.summary, 'the words a reader sees must match too');
      assert.deepEqual(
        got.not_checked,
        c.verdict.not_checked,
        'the same checks went unchecked, for the same stated reasons',
      );
      assert.equal(got.not_checked_line, c.verdict.not_checked_line);
      assert.equal(got.verdict_line, c.verdict.verdict_line);
    });
  }
});

test('what went unchecked is named, never summarised away', async () => {
  const receipt = BY_NAME['allow-settled'];
  const verdict = await verifyReceipt({ envelope: receipt.envelope, leaves: receipt.leaves });
  const names = verdict.not_checked.map((e) => e.name);
  assert.ok(names.includes('signer.attestation'));
  assert.ok(names.includes('settlement.ledger_inclusion'));
  assert.match(verdict.not_checked_line, /enclave attestation \(/);
  assert.match(verdict.not_checked_line, /no settlement proof was supplied with this receipt\)/);
  assert.ok(verdict.verdict_line.startsWith('Nothing was contradicted. Not checked: '));
  assert.doesNotMatch(verdict.verdict_line, /unconfigured/);
  for (const entry of verdict.not_checked) {
    const check = verdict.checks.find((c) => c.name === entry.name);
    assert.equal(entry.reason, check.detail, 'each reason is the check’s own detail');
  }
});

test('the level line names its level once, and the page must not add another', async () => {
  const receipt = BY_NAME['allow-settled'];
  const verdict = await verifyReceipt({ envelope: receipt.envelope, leaves: receipt.leaves });
  assert.ok(verdict.level_detail.startsWith('Level 1:'));
  assert.equal(verdict.level_detail.match(/evel 1/g).length, 1);
});

test('a receipt bundle carrying only its own action still joins the session', async (t) => {
  const c = verdictVectors().cases.find((x) => x.material.session_bundle);
  const receipt = BY_NAME[c.name];
  const leafIndex = receipt.envelope.session_locator.leaf_index;
  const scoped = {
    ...c.material.session_bundle,
    actions: c.material.session_bundle.actions.filter((a) => a.proof.leaf_index === leafIndex),
  };
  assert.equal(scoped.actions.length, 1, 'the receipt page ships exactly one action');

  await t.test('it reaches level 2', async () => {
    const verdict = await verifyReceipt(
      { envelope: receipt.envelope, leaves: receipt.leaves },
      { ...material(c.material), sessionBundle: scoped },
    );
    assert.equal(verdict.checks.find((x) => x.name === 'session.log_join').status, 'pass');
    assert.equal(verdict.level, 2);
  });

  await t.test('an unsealed session says so instead of reading as a bare level 1', async () => {
    const open = { ...scoped, session: { ...scoped.session, sealed: false } };
    const verdict = await verifyReceipt(
      { envelope: receipt.envelope, leaves: receipt.leaves },
      { ...material(c.material), sessionBundle: open },
    );
    const join = verdict.checks.find((x) => x.name === 'session.log_join');
    assert.equal(join.status, 'not_implemented');
    assert.match(join.detail, /is not sealed yet; level 2 becomes available after sealing/);
    assert.equal(verdict.level, 1);
  });

  await t.test('one action that is a different leaf does not join', async () => {
    const wrong = {
      ...scoped,
      actions: c.material.session_bundle.actions
        .filter((a) => a.proof.leaf_index !== leafIndex)
        .slice(0, 1),
    };
    const verdict = await verifyReceipt(
      { envelope: receipt.envelope, leaves: receipt.leaves },
      { ...material(c.material), sessionBundle: wrong },
    );
    const join = verdict.checks.find((x) => x.name === 'session.log_join');
    assert.equal(join.status, 'fail');
    assert.match(join.detail, /none of them is that leaf/);
  });
});

test('material the verifier did not bring becomes a named gap, never a pass', async () => {
  const receipt = BY_NAME['allow-settled'];
  const bare = await verifyReceipt({ envelope: receipt.envelope, leaves: receipt.leaves });
  const s = statuses(bare.checks);
  assert.equal(s['policy.document'], 'not_implemented');
  assert.equal(s['signer.attestation'], 'not_implemented');
  assert.equal(s['settlement.ledger_inclusion'], 'not_implemented');
  assert.equal(s['session.log_join'], 'not_implemented');
  assert.equal(bare.ok, true, 'nothing was contradicted');
  assert.equal(bare.complete, false, 'and plenty went unchecked');
  assert.equal(bare.level, 1);
});

test('an unattested signer is a stated finding, not a missing field', async () => {
  const receipt = BY_NAME['allow-settled-fake-rail'];
  const verdict = await verifyReceipt({ envelope: receipt.envelope, leaves: receipt.leaves });
  assert.equal(verdict.attested, false);
  assert.match(verdict.summary.signer, /unattested/);
});

test('every tamper case fails exactly the checks it declares', async (t) => {
  for (const c of tamperedVectors().cases) {
    await t.test(c.name, async () => {
      let failing;
      if (c.kind === 'receipt') {
        const verdict = await verifyReceipt({ envelope: c.envelope, leaves: c.leaves });
        failing = verdict.checks.filter((x) => x.status === 'fail').map((x) => x.name);
      } else {
        const res = await verifyDisclosure(c.disclosure, c.root);
        failing = res.failures.map((x) => x.name);
      }
      assert.deepEqual(failing.sort(), c.expected_failing_checks.slice().sort(), c.description);
    });
  }
});
