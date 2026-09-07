/**
 * The page itself reaches a verdict.
 *
 * A verifier that computes the right answer and then throws while rendering it
 * has verified nothing, so the template is exercised here rather than trusted.
 * The substitution mirrors `merkl.core.verify.render.render_verify_html`;
 * `tests/core/test_render.py` asserts the Python renderer does the same three
 * things, so the two cannot drift apart silently.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { REPO, bundleFile, receiptVectors, verdictVectors } from './vectors.mjs';
import { runPage } from './dom.mjs';

const TEMPLATE = readFileSync(path.join(REPO, 'merkl', 'core', 'verify', 'verify.html'), 'utf8');
const MODULE = readFileSync(
  path.join(REPO, 'merkl', 'core', 'verify', 'js', 'merkl-verify.js'),
  'utf8',
);

function render(bundle, title = 'test') {
  return TEMPLATE.replace(
    '__MERKL_VERIFY_JS__',
    MODULE.replace(/^export (?=(async function|function|class|const|let|var)\b)/gm, ''),
  )
    .replace('__BUNDLE__', JSON.stringify(bundle).replace(/<\//g, '<\\/'))
    .replace('__TITLE__', title);
}

test('a session bundle renders a verdict, an action table and a log', async () => {
  const { thrown, ids } = await runPage(render(bundleFile('session-v1.1.json')));
  assert.equal(thrown, null, String(thrown && thrown.stack));
  assert.match(ids['global-verdict'], /Verified|partly unchecked/);
  assert.match(ids['actions-tbody'], /Merkle path/, 'the actions table lost its rows once before');
  assert.match(ids['log-box'], /Log root/);
  assert.match(ids['algo-box'], /merkl verify/);
});

test('a v1.2 bundle leads with sentences, not hashes', async () => {
  const { thrown, ids } = await runPage(render(bundleFile('receipts-v1.2.json')));
  assert.equal(thrown, null, String(thrown && thrown.stack));
  assert.match(ids.stories, /MERKL RECEIPT/);
  assert.match(ids.stories, /Because/);
  assert.match(ids.stories, /Allowed by/);
  assert.match(ids.stories, /Paid|Asked/);
  assert.match(ids.lines, /Transaction authorization/);
  assert.match(ids.lines, /Ledger inclusion/);
  assert.match(ids.lines, /Level 1|Level 2/);
  assert.doesNotMatch(
    ids.stories,
    /[0-9a-f]{40}/,
    'no hash may appear above the fold; hashes live in the expandable detail',
  );
});

test('a receipt-only bundle needs no session', async () => {
  const receipt = bundleFile('receipts-v1.2.json').receipts[0];
  const { thrown, ids } = await runPage(
    render({ version: '1.2', receipts: [receipt], session: null, actions: [] }),
  );
  assert.equal(thrown, null, String(thrown && thrown.stack));
  assert.match(ids.stories, /MERKL RECEIPT/);
  assert.equal(ids['actions-tbody'].trim(), '', 'there is no session to show');
});

test('an unattested signer is shown loudly', async () => {
  const receipt = receiptVectors().cases.find((c) => c.name === 'allow-settled-fake-rail');
  const { thrown, ids } = await runPage(
    render({
      version: '1.2',
      session: null,
      actions: [],
      receipts: [{ envelope: receipt.envelope, leaves: receipt.leaves }],
    }),
  );
  assert.equal(thrown, null, String(thrown && thrown.stack));
  assert.match(ids.stories, /loud/);
  assert.match(ids.stories, /unattested/);
});

test('reasoning is labelled testimony', async () => {
  const { thrown, ids } = await runPage(render(bundleFile('receipts-v1.2.json')));
  assert.equal(thrown, null);
  assert.match(ids.stories, /Testimony, not proof/);
});

test('the checks a page could not run are named, not hidden', async () => {
  const { thrown, ids } = await runPage(render(bundleFile('receipts-v1.2.json')));
  assert.equal(thrown, null);
  assert.match(ids.gaps, /signer\.attestation/);
  assert.match(ids.gaps, /none of these is a failure, and none of them is a pass/i);
});

test('a tampered bundle says so in the badge', async () => {
  const bundle = JSON.parse(JSON.stringify(bundleFile('session-v1.1.json')));
  bundle.actions[0].timestamp = '2099-01-01T00:00:00+00:00';
  const { thrown, ids } = await runPage(render(bundle));
  assert.equal(thrown, null, String(thrown && thrown.stack));
  assert.match(ids['global-verdict'], /Contradicted/);
  assert.match(ids.headline, /does not hold together/);
});

test('the page reaches level 2 when the bundle carries the join', async () => {
  const verdicts = verdictVectors().cases;
  const joined = verdicts.find((c) => c.material.session_bundle);
  const receipt = receiptVectors().cases.find((c) => c.name === joined.name);
  const bundle = JSON.parse(JSON.stringify(joined.material.session_bundle));
  bundle.receipts = [{ envelope: receipt.envelope, leaves: receipt.leaves }];
  const { thrown, ids } = await runPage(render(bundle));
  assert.equal(thrown, null, String(thrown && thrown.stack));
  assert.match(ids.lines, /Level 2/);
});

test('a disclosure is rendered for exactly what it is', async () => {
  const receipt = receiptVectors().cases.find((c) => c.name === 'allow-settled');
  const { thrown, ids } = await runPage(
    render({ version: '1.2', session: null, actions: [], receipts: [], disclosure: receipt.disclosure }),
  );
  assert.equal(thrown, null, String(thrown && thrown.stack));
  assert.match(ids['disclosure-note'], /leaves were disclosed/);
  assert.match(ids['disclosure-note'], /compare it against the receipt/);
  assert.match(ids['disclosure-leaves'], /withheld/);
  assert.match(ids['disclosure-leaves'], /nothing at all about what it says/);
  assert.match(ids['global-verdict'], /Verified|partly unchecked/);
});

test('a disclosure against a doctored root contradicts', async () => {
  const receipt = receiptVectors().cases.find((c) => c.name === 'allow-settled');
  const disclosure = JSON.parse(JSON.stringify(receipt.disclosure));
  disclosure.root = '00'.repeat(32);
  const { thrown, ids } = await runPage(
    render({ version: '1.2', session: null, actions: [], receipts: [], disclosure }),
  );
  assert.equal(thrown, null, String(thrown && thrown.stack));
  assert.match(ids['global-verdict'], /Contradicted/);
});
