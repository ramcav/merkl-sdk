#!/usr/bin/env node
/**
 * `merkl-verify` — the JavaScript verifier, from a terminal.
 *
 * The same checks `merkl verify` runs, in the other implementation, over the
 * same file. That is the whole point of it: two implementations of one spec are
 * only worth having if a reader can actually run both and compare. A scenario
 * that ends "the Python verifier says it holds" has been checked once; a
 * scenario that ends with both saying so has been checked by two programs that
 * share no code.
 *
 * ```
 * node cli.mjs verify.html
 * node cli.mjs bundle.json --all
 * node cli.mjs receipt.json --validator validator-0=<hex> --quorum 2
 * ```
 *
 * Exit codes match the Python command:
 *   0  nothing was contradicted
 *   1  a check failed, or --require-complete was asked for and something did not run
 *   2  the input could not be read at all
 *
 * Trust anchors are flags, never values read out of the file being checked, and
 * a flag nobody passed produces a named unchecked line rather than a pass.
 */

import { readFileSync } from 'node:fs';

import { verifyBundle, PASS } from './merkl-verify.js';

const BUNDLE_IN_PAGE = /^const BUNDLE = (.*);\s*$/m;

const MARK = { pass: '  ok  ', fail: ' FAIL ', not_implemented: '  --  ' };

function usage() {
  console.error(
    'usage: merkl-verify <receipt.json|bundle.json|verify.html> [--all] [--json]\n' +
      '                    [--require-complete] [--policy FILE] [--admin-key HEX]\n' +
      '                    [--proof FILE] [--pcr N=HEX]... [--validator NAME=HEX]...\n' +
      '                    [--quorum N] [--now ISO8601] [--max-age SECONDS]',
  );
}

function parseArgs(argv) {
  const opts = {
    file: null,
    all: false,
    json: false,
    requireComplete: false,
    policy: null,
    adminKey: null,
    proof: null,
    pcrs: {},
    validators: {},
    quorum: 0,
    now: null,
    maxAge: null,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => argv[(i += 1)];
    if (arg === '--all') opts.all = true;
    else if (arg === '--json') opts.json = true;
    else if (arg === '--require-complete') opts.requireComplete = true;
    else if (arg === '--policy') opts.policy = next();
    else if (arg === '--admin-key') opts.adminKey = next();
    else if (arg === '--proof') opts.proof = next();
    else if (arg === '--pcr') {
      const [index, hex] = splitPair(next());
      opts.pcrs[Number(index)] = hex.toLowerCase();
    } else if (arg === '--validator') {
      const [name, hex] = splitPair(next());
      opts.validators[name] = hex.toLowerCase();
    } else if (arg === '--quorum') opts.quorum = Number(next());
    else if (arg === '--now') opts.now = next();
    else if (arg === '--max-age') opts.maxAge = Number(next());
    else if (arg.startsWith('-')) throw new Error(`unknown flag ${arg}`);
    else if (opts.file === null) opts.file = arg;
    else throw new Error('one file at a time');
  }
  return opts;
}

function splitPair(value) {
  const at = String(value).indexOf('=');
  return at < 0 ? [value, ''] : [value.slice(0, at), value.slice(at + 1)];
}

/**
 * Read a bundle out of a `.json` file or a rendered `verify.html`.
 *
 * The page an auditor was emailed is itself a valid input, exactly as it is for
 * `merkl verify`: the two entry points read the same bytes, so disagreeing with
 * the page is something you can check rather than something you take on faith.
 */
export function loadInput(path) {
  const text = readFileSync(path, 'utf8');
  if (/\.html?$/i.test(path)) {
    const match = BUNDLE_IN_PAGE.exec(text);
    if (match === null) throw new Error(`${path} does not carry an embedded Merkl bundle`);
    return JSON.parse(match[1].replace(/<\\\//g, '</'));
  }
  const data = JSON.parse(text);
  if (Array.isArray(data)) return { version: '1.2', receipts: data, session: null, actions: [] };
  if (data === null || typeof data !== 'object') throw new Error(`${path} is not an object`);
  if ('envelope' in data && 'leaves' in data) {
    return { version: '1.2', receipts: [data], session: null, actions: [] };
  }
  return data;
}

function readJson(path) {
  return path ? JSON.parse(readFileSync(path, 'utf8')) : null;
}

function wrap(text, width = 78) {
  const lines = [];
  let current = '';
  for (const word of String(text).split(/\s+/)) {
    if (current.length + word.length + 1 > width && current.trim()) {
      lines.push(current.trimEnd());
      current = '';
    }
    current += `${word} `;
  }
  if (current.trim()) lines.push(current.trimEnd());
  return lines;
}

function pad(label) {
  return label.padStart(12, ' ');
}

function printVerdict(verdict, showAll) {
  console.log('');
  console.log(`receipt ${verdict.receipt_id}`);
  console.log('-'.repeat(72));
  for (const [label, key] of [
    ['Told to', 'instructed'],
    ['Allowed by', 'rule'],
    ['Approved by', 'approved'],
    ['Settled', 'settled'],
    ['When', 'when'],
    ['Signer', 'signer'],
    ['Reasoning', 'testimony'],
  ]) {
    const text = verdict.summary[key];
    const body = text ? wrap(text).join(`\n${' '.repeat(14)}`) : '(the receipt does not say)';
    console.log(`${pad(label)}  ${body}`);
  }
  console.log('');
  console.log(`${pad('Authorization')}  ${verdict.settlement.transaction_authorization}`);
  console.log(`${pad('')}  ${verdict.settlement.transaction_authorization_detail}`);
  console.log(`${pad('Ledger')}  ${verdict.settlement.ledger_inclusion}`);
  console.log(`${pad('')}  ${verdict.settlement.ledger_inclusion_detail}`);
  console.log(`${pad('Level')}  ${verdict.level} — ${verdict.level_detail}`);
  console.log('');
  let passed = 0;
  for (const c of verdict.checks) {
    if (c.status === PASS) passed += 1;
    if (!showAll && c.status === PASS) continue;
    console.log(`${MARK[c.status]} ${c.name.padEnd(38)} ${c.detail}`);
  }
  if (!showAll) console.log(`${MARK[PASS]} ${passed} further checks passed (--all to list them)`);
}

export async function main(argv) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (err) {
    console.error(String(err.message));
    usage();
    return 2;
  }
  if (opts.file === null) {
    usage();
    return 2;
  }

  let bundle;
  try {
    bundle = loadInput(opts.file);
  } catch (err) {
    console.error(`cannot read ${opts.file}: ${err.message}`);
    return 2;
  }

  const pinnedPcrs = Object.keys(opts.pcrs).length > 0;
  const receiptOptions = {
    attestationTrust: pinnedPcrs
      ? { pcrs: opts.pcrs, maxAgeSeconds: opts.maxAge ?? null }
      : null,
    now: opts.now ?? (pinnedPcrs ? new Date().toISOString() : null),
    validatorTrust:
      Object.keys(opts.validators).length > 0
        ? { validators: opts.validators, quorum: opts.quorum }
        : null,
    adminPublicKey: opts.adminKey,
  };
  const policyDocument = readJson(opts.policy);
  const settlementProof = readJson(opts.proof);
  if (policyDocument !== null) receiptOptions.policyDocument = policyDocument;
  if (settlementProof !== null) receiptOptions.settlementProof = settlementProof;

  let whole;
  try {
    whole = await verifyBundle(bundle, { receiptOptions });
  } catch (err) {
    console.error(`cannot verify ${opts.file}: ${err.message}`);
    return 2;
  }
  if (whole.receipts.length === 0 && whole.log === null) {
    console.error(`${opts.file} carries neither a receipt nor a session`);
    return 2;
  }

  if (opts.json) {
    console.log(
      JSON.stringify(
        {
          source: opts.file,
          ok: whole.ok,
          complete: whole.complete,
          receipts: whole.receipts.map((v) => ({
            receipt_id: v.receipt_id,
            ok: v.ok,
            complete: v.complete,
            level: v.level,
            settlement: v.settlement,
            attested: v.attested,
            summary: v.summary,
            checks: v.checks.map((c) => ({ name: c.name, status: c.status, detail: c.detail })),
          })),
          log: whole.log
            ? { ok: whole.log.result.ok, complete: whole.log.result.complete }
            : null,
        },
        null,
        2,
      ),
    );
  } else {
    for (const verdict of whole.receipts) printVerdict(verdict, opts.all);
    if (whole.log) {
      console.log('');
      console.log('session log');
      console.log('-'.repeat(72));
      for (const c of whole.log.result.checks) {
        if (!opts.all && c.status === PASS) continue;
        console.log(`${MARK[c.status]} ${c.name.padEnd(38)} ${c.detail}`);
      }
      const bad = whole.log.actions.filter((a) => !a.ok).length;
      console.log(`${whole.log.actions.length - bad} of ${whole.log.actions.length} actions verified`);
    }
    console.log('');
    console.log(whole.ok ? 'nothing was contradicted' : 'SOMETHING WAS CONTRADICTED');
    console.log(
      whole.complete
        ? 'every check ran'
        : 'some checks did not run — listed above with --, and none of them is a pass',
    );
  }

  if (!whole.ok) return 1;
  return opts.requireComplete && !whole.complete ? 1 : 0;
}

if (process.argv[1] && process.argv[1].endsWith('cli.mjs')) {
  process.exitCode = await main(process.argv.slice(2));
}
