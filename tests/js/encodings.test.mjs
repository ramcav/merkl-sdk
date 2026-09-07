/** The byte-level encodings, against the same fixtures the Python suite reads. */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  actionLeafHash,
  buildLeft,
  buildRight,
  buildRoot,
  canonicalJson,
  canonicalHashHex,
  deriveRoot,
  merkleRoot,
  receiptLeafHash,
  toHex,
  sha256,
  utf8,
} from '../../merkl/core/verify/js/merkl-verify.js';
import { actionLeafVectors, merkleVectors, receiptLeafVectors } from './vectors.mjs';

test('canonical JSON is Python json.dumps, escape for escape', async (t) => {
  await t.test('keys sort and separators are tight', () => {
    assert.equal(canonicalJson({ b: 1, a: 2 }), '{"a":2,"b":1}');
  });
  await t.test('every non-ASCII character becomes a lowercase \\uXXXX escape', () => {
    assert.equal(canonicalJson('café ☕'), '"caf\\u00e9 \\u2615"');
  });
  await t.test('the short escapes are the ones Python uses', () => {
    assert.equal(canonicalJson('a\tb\nc"d\\e'), '"a\\tb\\nc\\"d\\\\e"');
  });
  await t.test('null is the literal, not an empty string', () => {
    assert.equal(canonicalJson(null), 'null');
    assert.equal(canonicalJson(undefined), 'null');
  });
  await t.test('a hash of nested content matches a hand-computed digest', async () => {
    const value = { z: [1, 2, { y: null }], a: 'ü' };
    const expected = toHex(await sha256(utf8(canonicalJson(value))));
    assert.equal(await canonicalHashHex(value), expected);
  });
});

test('Merkle trees fold the way the vectors say', async (t) => {
  for (const c of merkleVectors().cases) {
    await t.test(c.name, async () => {
      assert.equal(await merkleRoot(c.leaves), c.root);
      for (const proof of c.proofs) {
        const derived = await deriveRoot(c.leaves[proof.index], proof.siblings, proof.directions);
        assert.equal(derived, c.root, `leaf ${proof.index} does not prove into the root`);
      }
      for (const proof of c.subtree_proofs) {
        const derived = await deriveRoot(c.leaves[proof.index], proof.siblings, proof.directions);
        assert.equal(derived, proof.subtree_root);
      }
    });
  }
});

test('a proof with an edited sibling lands somewhere else', async () => {
  const c = merkleVectors().cases.find((x) => x.proofs.some((p) => p.siblings.length));
  const proof = c.proofs.find((p) => p.siblings.length);
  const edited = proof.siblings.slice();
  edited[0] = edited[0].slice(0, -1) + (edited[0].endsWith('0') ? '1' : '0');
  const derived = await deriveRoot(c.leaves[proof.index], edited, proof.directions);
  assert.notEqual(derived, c.root);
});

test('merkl-leaf-v1 is byte-identical to the frozen encoding', async (t) => {
  for (const c of actionLeafVectors().cases) {
    await t.test(c.name, async () => {
      const fields = { ...c.fields, drift_score_str: c.fields.drift_score };
      assert.equal(await actionLeafHash(fields), c.leaf);
    });
  }
});

test('merkl-receipt-leaf-v1 binds the leaf name into the hash', async (t) => {
  for (const c of receiptLeafVectors().cases) {
    await t.test(c.name, async () => {
      assert.equal(await receiptLeafHash(c.leaf_name, c.content), c.leaf);
    });
  }
});

test('the same content under two leaf names hashes differently', async () => {
  const a = await receiptLeafHash('instruction', { x: 1 });
  const b = await receiptLeafHash('intent', { x: 1 });
  assert.notEqual(a, b);
});

test('the halves fold from the eight committed leaf hashes', async () => {
  const hashes = [];
  for (let i = 0; i < 7; i++) hashes.push(await receiptLeafHash(`leaf-${i}`, { i }));
  hashes.push(hashes[6]);
  const left = await buildLeft(hashes);
  const right = await buildRight(hashes);
  const root = await buildRoot(left, right);
  assert.equal(root.length, 64);
  assert.notEqual(left, right);
});
