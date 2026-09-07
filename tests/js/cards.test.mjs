/**
 * ReceiptCard JSON agrees with the Python generator, case for case.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { receiptCard, verifyReceipt } from '../../merkl/core/verify/js/merkl-verify.js';
import { load, receiptVectors } from './vectors.mjs';

const CARDS = load('cards.json');
const VERDICTS = load('verdicts.json');
const RECEIPTS = Object.fromEntries(receiptVectors().cases.map((c) => [c.name, c]));
const MATERIAL = Object.fromEntries(VERDICTS.cases.map((c) => [c.name, c.material]));

test('receiptCard matches the committed fixture', async (t) => {
  for (const c of CARDS.cases) {
    await t.test(c.name, async () => {
      const receipt = RECEIPTS[c.receipt ?? c.name];
      const material = MATERIAL[c.name];
      const full = await verifyReceipt(receipt, {
        settlementProof: material.settlement_proof,
        validatorTrust: material.validator_trust,
        policyDocument: material.policy_document,
        adminPublicKey: material.admin_public_key,
        sessionBundle: material.session_bundle,
      });
      assert.deepEqual(receiptCard(full, receipt.envelope, receipt.leaves), c.card);
    });
  }
});

test('rulesPassedPhrase reads plainly and matches the Python wording', async () => {
  const { rulesPassedPhrase } = await import('../../merkl/core/verify/js/merkl-verify.js');
  assert.equal(rulesPassedPhrase([{ outcome: 'pass' }, { outcome: 'pass' }, { outcome: 'pass' }]), 'all 3 rules passed');
  assert.equal(
    rulesPassedPhrase([...Array(10)].map(() => ({ outcome: 'pass' })).concat([{ outcome: 'skip' }])),
    'all 10 rules passed · 1 did not apply',
  );
  assert.equal(rulesPassedPhrase([{ outcome: 'pass' }, { outcome: 'fail' }]), '1 of 2 rules passed');
  assert.equal(rulesPassedPhrase(null), 'no rules ran');
});

test('rateString computes the rate the Python card prints, digit for digit', async () => {
  const { rateString } = await import('../../merkl/core/verify/js/merkl-verify.js');
  for (const c of CARDS.rate_cases) {
    assert.equal(rateString(c.spent, c.bought), c.rate, `${c.spent} / ${c.bought}`);
  }
  // A rate needs two sides. Nothing shaped like a number comes back without them.
  assert.equal(rateString('0', '100'), null);
  assert.equal(rateString('100', '0'), null);
});

test('a settled trade reads Bought, Sold against its limit, and Rate', () => {
  const settled = CARDS.cases.find((c) => c.name === 'swap-settled');
  assert.deepEqual(
    settled.card.body.map((l) => l.label),
    ['Bought', 'Sold', 'Rate', 'From', 'By', 'On', 'Ref'],
  );
  // A trade's destination is the treasury, so the card never says "To".
  assert.equal(settled.card.body.some((l) => l.label === 'To'), false);

  const refused = CARDS.cases.find((c) => c.name === 'swap-denied-may-not-trade');
  assert.deepEqual(
    refused.card.body.map((l) => l.label),
    ['Asked', 'From', 'By'],
  );
  assert.match(refused.card.body[0].value, /^to buy .+ for up to /);
  // The rule that refused it is the one that failed, never one that was skipped.
  assert.equal(
    refused.card.provenance.find((l) => l.label === 'Allowed by').value,
    'Refused by rule: may swap',
  );
});
