/** Approval assertions and quorum counting (plan D11, spec section 3.3). */

import test from 'node:test';
import assert from 'node:assert/strict';

import { fromHex, verifyAssertion, verifyQuorum } from '../../merkl/core/verify/js/merkl-verify.js';
import { approvalVectors } from './vectors.mjs';

const VECTORS = approvalVectors();

test('every committed assertion case reaches the verdict the fixture records', async (t) => {
  for (const c of VECTORS.cases) {
    await t.test(c.name, async () => {
      const check = await verifyAssertion(c.assertion, fromHex(c.challenge), c.credential);
      assert.equal(
        check.valid,
        c.expected_valid,
        `${c.name}: ${check.detail} — ${c.description}`,
      );
    });
  }
});

test('quorum counts distinct approvers the policy names', async (t) => {
  for (const c of VECTORS.quorum_cases) {
    await t.test(c.name, async () => {
      const quorum = await verifyQuorum(
        c.assertions,
        fromHex(c.challenge),
        c.approvers,
        c.quorum,
      );
      assert.equal(quorum.reached, c.expected_reached, c.description);
      assert.deepEqual(quorum.accepted.slice().sort(), c.expected_accepted.slice().sort());
    });
  }
});

test('a valid signature from someone the policy does not name is nothing', async () => {
  const c = VECTORS.cases.find((x) => x.name === 'ed25519-valid');
  const quorum = await verifyQuorum([c.assertion], fromHex(c.challenge), [], 1);
  assert.equal(quorum.reached, false);
  assert.equal(quorum.accepted.length, 0);
});

test('five assertions from one approver are one approval', async () => {
  const c = VECTORS.cases.find((x) => x.name === 'ed25519-valid');
  const quorum = await verifyQuorum(
    [c.assertion, c.assertion, c.assertion],
    fromHex(c.challenge),
    [c.credential],
    2,
  );
  assert.equal(quorum.accepted.length, 1);
  assert.equal(quorum.reached, false);
});
