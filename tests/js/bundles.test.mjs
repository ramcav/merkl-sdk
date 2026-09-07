/**
 * Proof bundles merkl-api actually exported, and mutations of them.
 *
 * The fixtures are real server output rather than anything this repository
 * generated, so passing them means this implementation reads what the notary
 * writes — including `drift_score_str` and the exact `timestamp` string, the two
 * fields a re-rendered value silently breaks.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  actionLeafHash,
  auditEntryHash,
  bindingLeafHash,
  canonicalHashHex,
  checkpointBodyMatches,
  evidenceRecords,
  verifyEvidence,
  verifyLogBundle,
  verifyLogInclusion,
} from '../../merkl/core/verify/js/merkl-verify.js';
import { bundleCases, bundleFile, statuses } from './vectors.mjs';

function bundleOf(c) {
  return c.tamper === null ? bundleFile(c.file) : c.bundle;
}

test('every bundle case reports the statuses the fixture records', async (t) => {
  for (const c of bundleCases().cases) {
    await t.test(c.name, async () => {
      const verdict = await verifyLogBundle(bundleOf(c));
      assert.deepEqual(statuses(verdict.result.checks), c.checks, c.description);
      assert.equal(verdict.result.ok, c.ok);
      assert.equal(verdict.result.complete, c.complete);
      if (c.fails) {
        assert.deepEqual(
          verdict.result.failures.map((x) => x.name).sort(),
          c.fails.slice().sort(),
        );
      }
    });
  }
});

test('per-action readings match the Python ones', async (t) => {
  for (const c of bundleCases().cases.filter((x) => x.tamper === null)) {
    await t.test(c.name, async () => {
      const verdict = await verifyLogBundle(bundleFile(c.file));
      assert.equal(verdict.actions.length, c.actions.length);
      for (let i = 0; i < c.actions.length; i++) {
        const got = verdict.actions[i];
        const want = c.actions[i];
        assert.equal(got.computed_leaf, want.computed_leaf);
        assert.equal(got.leaf_matches, want.leaf_matches);
        assert.equal(got.proof_ok, want.proof_ok);
        assert.equal(got.derived_root, want.derived_root);
        assert.equal(got.ok, want.ok);
      }
    });
  }
});

test('the exact drift_score string is what the leaf hashes', async () => {
  const bundle = bundleFile('session-v1.1.json');
  const action = { ...bundle.actions[0] };
  const withString = await actionLeafHash(action);
  delete action.drift_score_str;
  action.drift_score = 0;
  assert.notEqual(await actionLeafHash(action), withString);
});

test('the audit entry recomputes from the bundle', async () => {
  const bundle = bundleFile('session-v1.1.json');
  assert.equal(await auditEntryHash(bundle.audit_log), bundle.audit_log.current_hash);
});

test('the RFC 6962 proof folds to the checkpoint root', async () => {
  const bundle = bundleFile('session-v1.1.json');
  const read = await verifyLogInclusion(bundle.transparency.log_inclusion);
  assert.equal(read.ok, true, read.detail);
});

test('a checkpoint body claiming another root is caught', () => {
  const bundle = bundleFile('session-v1.1.json');
  const cp = { ...bundle.transparency.checkpoint };
  assert.equal(checkpointBodyMatches(cp).ok, true);
  cp.root_hash = '00'.repeat(32);
  assert.equal(checkpointBodyMatches(cp).ok, false);
});

test('the continuation binding is tagged', async () => {
  const a = await bindingLeafHash('s', '00'.repeat(32), 'force_seal');
  const b = await bindingLeafHash('s', '00'.repeat(32), 'idle_timeout');
  assert.notEqual(a, b);
});

test('an evidence record that rehashes to the leaf is the document', async () => {
  const rawInput = { query: 'SELECT 1', unicode: 'café ☕' };
  const rawOutput = ['ok', 42];
  const action = {
    action_id: 'a',
    tool_name: 'query_db',
    input_hash: await canonicalHashHex(rawInput),
    output_hash: await canonicalHashHex(rawOutput),
  };
  const readings = await verifyEvidence(
    [{ action_id: 'a', input: rawInput, output: rawOutput }],
    [action],
  );
  assert.equal(readings[0].verdict, 'ok');
});

test('one edited byte and the record stops being the document', async () => {
  const action = {
    action_id: 'a',
    tool_name: 'query_db',
    input_hash: await canonicalHashHex({ query: 'SELECT 1' }),
    output_hash: await canonicalHashHex(null),
  };
  const readings = await verifyEvidence(
    [{ action_id: 'a', input: { query: 'SELECT 2' }, output: null }],
    [action],
  );
  assert.equal(readings[0].verdict, 'bad');
  assert.match(readings[0].detail, /INPUT hash mismatch/);
});

test('a record for another bundle is unknown, not failed', async () => {
  const readings = await verifyEvidence([{ action_id: 'elsewhere' }], []);
  assert.equal(readings[0].verdict, 'unknown');
});

test('an unparseable evidence line is reported, not skipped', async () => {
  const readings = await verifyEvidence(evidenceRecords('{not json}\n'), []);
  assert.equal(readings[0].verdict, 'bad');
});

test('a bundle with no log is level 1, not a failure', async () => {
  const bundle = { ...bundleFile('session-v1.1.json') };
  delete bundle.transparency;
  delete bundle.audit_log;
  const verdict = await verifyLogBundle(bundle);
  const s = statuses(verdict.result.checks);
  assert.equal(s['log.audit_entry'], 'not_implemented');
  assert.equal(s['log.inclusion'], 'not_implemented');
  assert.equal(verdict.result.ok, true);
  assert.equal(verdict.result.complete, false);
});
