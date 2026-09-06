/**
 * Loading the committed fixtures, and nothing else.
 *
 * The JavaScript suite reads exactly the files `tests/core/test_vectors.py`
 * reads. That is the whole design: one vector set, two implementations, and a
 * disagreement that shows up as a failing test rather than as a support ticket.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const REPO = path.resolve(HERE, '..', '..');
export const VECTORS = path.join(REPO, 'merkl', 'core', 'vectors');

export function load(...parts) {
  return JSON.parse(readFileSync(path.join(VECTORS, ...parts), 'utf8'));
}

export function loadText(...parts) {
  return readFileSync(path.join(VECTORS, ...parts), 'utf8');
}

export const merkleVectors = () => load('merkle.json');
export const actionLeafVectors = () => load('action_leaf.json');
export const receiptLeafVectors = () => load('receipt_leaf.json');
export const approvalVectors = () => load('approvals.json');
export const policyVectors = () => load('policies.json');
export const receiptVectors = () => load('receipts.json');
export const verdictVectors = () => load('verdicts.json');
export const tamperedVectors = () => load('tampered.json');
export const attestationCases = () => load('attestation', 'cases.json');
export const bundleCases = () => load('bundles', 'cases.json');
export const bundleFile = (name) => load('bundles', name);

/** The trust inputs a case pins, in the shape `verifyAttestation` takes. */
export function attestationTrust(caseTrust, defaultRootPem) {
  return {
    pcrs: caseTrust.pcrs,
    maxAgeSeconds: caseTrust.max_age_seconds,
    requireProductionMode: caseTrust.require_production_mode,
    rootPem:
      caseTrust.root_pem_file === 'aws-nitro-root-g1.pem'
        ? defaultRootPem
        : loadText('attestation', caseTrust.root_pem_file),
  };
}

/** Every check name mapped to its status — the cross-implementation contract. */
export function statuses(checks) {
  return Object.fromEntries(checks.map((c) => [c.name, c.status]));
}
