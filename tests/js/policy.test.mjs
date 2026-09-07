/** Policy document admin signatures — legacy and assertion-shaped (plan D16, extended). */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  policyDocumentCheck,
  unenforceableRules,
  verifyPolicySignature,
} from '../../merkl/core/verify/js/merkl-verify.js';
import { policyVectors } from './vectors.mjs';

const VECTORS = policyVectors();

test('every committed policy-signature case reaches the verdict the fixture records', async (t) => {
  for (const c of VECTORS.cases) {
    await t.test(c.name, async () => {
      const opts = {};
      if (c.pinned_admin_public_key) opts.adminPublicKey = c.pinned_admin_public_key;
      if (c.pinned_admin) opts.admin = c.pinned_admin;
      const result = await verifyPolicySignature(c.signed_policy, opts);
      assert.equal(result.valid, c.expected_valid, `${c.name}: ${result.detail} — ${c.description}`);
    });
  }
});

test('a legacy document unpinned trusts its own admin_public_key', async () => {
  const c = VECTORS.cases.find((x) => x.name === 'legacy-ed25519-unpinned-trusts-the-document');
  const result = await verifyPolicySignature(c.signed_policy);
  assert.equal(result.valid, true);
});

test('passing both admin and adminPublicKey is refused', async () => {
  const c = VECTORS.cases.find((x) => x.name === 'legacy-ed25519-valid');
  await assert.rejects(() =>
    verifyPolicySignature(c.signed_policy, {
      adminPublicKey: c.pinned_admin_public_key,
      admin: { credential_type: 'ed25519', public_key: c.pinned_admin_public_key },
    }),
  );
});

test('a webauthn admin signature is verified with the same challenge as an approver assertion', async () => {
  const c = VECTORS.cases.find((x) => x.name === 'webauthn-admin-valid');
  assert.equal(typeof c.signed_policy.signature, 'object');
  assert.equal(c.signed_policy.signature.approver_id, 'admin');
  const result = await verifyPolicySignature(c.signed_policy, { admin: c.pinned_admin });
  assert.equal(result.valid, true);
});

test('every committed document-rule case reports the sentences the fixture pins', async (t) => {
  for (const c of VECTORS.document_cases) {
    await t.test(c.name, () => {
      assert.deepEqual(
        unenforceableRules(c.signed_policy.document),
        c.expected_findings,
        c.description,
      );
    });
  }
});

test('a dead rule is a finding even though the admin signature verifies', async (t) => {
  for (const c of VECTORS.document_cases.filter((x) => x.expected_findings.length)) {
    await t.test(c.name, async () => {
      const signature = await verifyPolicySignature(c.signed_policy);
      assert.equal(signature.valid, true, 'the fixture is a properly signed policy');

      const [documentCheck, policy] = await policyDocumentCheck(
        { policy_hash: c.policy_hash },
        c.signed_policy,
        c.signed_policy.signer_public_key,
      );
      assert.equal(documentCheck.status, 'fail');
      assert.equal(documentCheck.detail, c.expected_findings[0]);
      assert.equal(policy, null, 'an unenforceable document says nothing about approvers');
    });
  }
});

test('an enforceable document still passes the policy.document check', async () => {
  const c = VECTORS.document_cases.find((x) => x.name === 'enforceable-document');
  const [documentCheck, policy] = await policyDocumentCheck(
    { policy_hash: c.policy_hash },
    c.signed_policy,
    c.signed_policy.signer_public_key,
  );
  assert.equal(documentCheck.status, 'pass', documentCheck.detail);
  assert.equal(policy.version, '2026.03.0');
});
