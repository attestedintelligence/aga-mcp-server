/**
 * Conformance gate: every valid fixture must VERIFY (with provenance when pinned);
 * every negative fixture must FAIL. Drives the canonical reference verifier.
 *   node fixtures/run-conformance.mjs    # exit 0 = pass, 1 = fail
 */
import { verifySepBundle } from '../aga-receipt-spec/verify/verify-sep.mjs';
import { readFileSync } from 'node:fs';

const load = n => JSON.parse(readFileSync(new URL(`./${n}`, import.meta.url), 'utf8'));
const cases = [
  { file: 'valid_minimal.json', expect: 'VERIFIED', pin: true },
  { file: 'valid_denied.json', expect: 'VERIFIED', pin: true },
  { file: 'tampered.json', expect: 'FAILED' },
  { file: 'truncated.json', expect: 'FAILED' },
  { file: 'wrong_key.json', expect: 'FAILED' },
  { file: 'small_order_key.json', expect: 'FAILED' }, // small-order (identity) public key — every stack must reject
];

let fail = 0;
for (const c of cases) {
  const b = load(c.file);
  const res = verifySepBundle(b, c.pin ? b.public_key : undefined);
  const ok = res.verdict === c.expect && (c.pin ? res.issuerVerified === true : true);
  if (!ok) fail++;
  console.log(`${ok ? 'OK ' : 'XX '} ${c.file}: ${res.verdict}${c.pin ? ` (issuerVerified=${res.issuerVerified})` : ''} — expected ${c.expect}`);
}
console.log(fail ? `\nCONFORMANCE FAILED (${fail}/${cases.length})` : `\nCONFORMANCE PASSED (${cases.length}/${cases.length})`);
process.exit(fail ? 1 : 0);
