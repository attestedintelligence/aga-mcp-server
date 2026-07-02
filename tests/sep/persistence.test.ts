/**
 * OPT-IN restart persistence for the SEP evidence ledger (prototype).
 *
 * Proves the durability contract WITHOUT touching the evidence core: persistence only SAVES already-
 * signed receipts and REPLAYS them. Covered here:
 *   - record N with persistence on -> a NEW gateway replaying the SAME path exportBundle()s a bundle
 *     that VERIFIES, with the SAME receipt count AND the SAME merkle_root as pre-restart (the explicit
 *     cross-restart proof: merkle_root(pre) === merkle_root(post) and both VERIFIED);
 *   - a receipt appended AFTER restart chains correctly and the whole bundle still verifies;
 *   - a TAMPERED committed line (bad signature / extra field / foreign key) is REJECTED LOUDLY on
 *     replay (throws ReceiptLogError) — never silently loaded;
 *   - a truncated/partial final line (crash mid-append) is DROPPED and the rest replays;
 *   - persistence OFF is byte-identical to today: no file is written, and the bundle is deep-equal to
 *     the persisted gateway's bundle for identical inputs.
 *
 * Cross-restart verification requires the gateway to resume with the SAME signing key, so every
 * "restart" here reconstructs the gateway from the SAME seed (the stable-key deployment posture).
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, readFileSync, writeFileSync, appendFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SepGateway } from '../../src/sep/bundle.js';
import { signerFromSeed } from '../../src/sep/crypto.js';
import { verifySepBundle } from '../../src/sep/verify.js';
import { ReceiptLogError } from '../../src/sep/persistence.js';

const SEED = new Uint8Array(32).fill(7);
const OTHER_SEED = new Uint8Array(32).fill(19);

/** Deterministic, non-decreasing, RFC-3339 .sssZ clock starting at second `base`. */
const mkClock = (base: number) => {
  let s = base;
  return () => new Date(Date.UTC(2026, 2, 19, 12, 0, s++)).toISOString();
};
const mkId = (base: number) => {
  let i = base;
  return () => `id-${i++}`;
};

/** Construct a gateway; SEED by default (same key across "restarts" so the bundle verifies). */
function gateway(persistPath: string | undefined, opts: { seed?: Uint8Array; clockBase?: number; idBase?: number } = {}) {
  return new SepGateway({
    gatewayId: 'gw-persist-test',
    signer: signerFromSeed(opts.seed ?? SEED),
    clock: mkClock(opts.clockBase ?? 0),
    idGen: mkId(opts.idBase ?? 0),
    persistPath,
  });
}

let dir: string;
let logPath: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aga-persist-'));
  logPath = join(dir, 'ledger.jsonl');
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('SEP persistence — replay produces an identical, verifiable ledger across restart', () => {
  it('records N with persistence on; a NEW gateway from the same path verifies with SAME count + SAME merkle_root', () => {
    const N = 5;
    const gw1 = gateway(logPath, { clockBase: 0, idBase: 0 });
    for (let i = 0; i < N; i++) {
      gw1.record({ tool_name: `tool_${i}`, decision: i % 2 ? 'DENIED' : 'PERMITTED', reason: `r${i}`, request_id: `req-${i}` });
    }
    const pre = gw1.exportBundle();
    gw1.close();

    expect(verifySepBundle(pre).verdict).toBe('VERIFIED');
    expect(pre.receipts.length).toBe(N);

    // "Restart": a brand-new gateway, same path, same key.
    const gw2 = gateway(logPath, { clockBase: 200, idBase: 500 });
    expect(gw2.count).toBe(N);
    const post = gw2.exportBundle();
    gw2.close();

    // The explicit cross-restart proof.
    expect(post.receipts.length).toBe(N);
    expect(post.merkle_root).toBe(pre.merkle_root);
    expect(verifySepBundle(post).verdict).toBe('VERIFIED');
    // Provenance also survives when pinned to the (stable) gateway key.
    expect(verifySepBundle(post, post.public_key).issuerVerified).toBe(true);
    // Receipt bytes are identical (not merely equivalent) across the restart.
    expect(post.receipts).toEqual(pre.receipts);
  });

  it('a receipt appended AFTER restart chains correctly and the whole bundle still verifies', () => {
    const gw1 = gateway(logPath, { clockBase: 0, idBase: 0 });
    gw1.record({ tool_name: 'a', decision: 'PERMITTED', reason: 'ok', request_id: '1' });
    gw1.record({ tool_name: 'b', decision: 'PERMITTED', reason: 'ok', request_id: '2' });
    gw1.close();

    const gw2 = gateway(logPath, { clockBase: 100, idBase: 100 });
    expect(gw2.count).toBe(2);
    gw2.record({ tool_name: 'c', decision: 'DENIED', reason: 'blocked', request_id: '3' });
    const bundle = gw2.exportBundle();
    gw2.close();

    expect(bundle.receipts.length).toBe(3);
    expect(verifySepBundle(bundle).verdict).toBe('VERIFIED');

    // And a THIRD gateway replaying the now-3-receipt log still verifies (chain intact end to end).
    const gw3 = gateway(logPath, { clockBase: 300, idBase: 300 });
    expect(gw3.count).toBe(3);
    const again = gw3.exportBundle();
    gw3.close();
    expect(again.merkle_root).toBe(bundle.merkle_root);
    expect(verifySepBundle(again).verdict).toBe('VERIFIED');
  });

  it('a TAMPERED committed line (flipped signature) is REJECTED LOUDLY on replay', () => {
    const gw1 = gateway(logPath, { clockBase: 0, idBase: 0 });
    gw1.record({ tool_name: 'a', decision: 'PERMITTED', reason: 'ok', request_id: '1' });
    gw1.record({ tool_name: 'b', decision: 'PERMITTED', reason: 'ok', request_id: '2' });
    gw1.close();

    const lines = readFileSync(logPath, 'utf8').split('\n').filter(Boolean);
    const r0 = JSON.parse(lines[0]);
    const sig: string = r0.signature;
    r0.signature = sig.slice(0, -1) + (sig.slice(-1) === '0' ? '1' : '0'); // still valid JSON, bad signature
    lines[0] = JSON.stringify(r0);
    writeFileSync(logPath, lines.join('\n') + '\n');

    expect(() => gateway(logPath)).toThrow(ReceiptLogError);
    expect(() => gateway(logPath)).toThrow(/signature verification failed/);
  });

  it('a committed line with an EXTRA field (non-canonical schema) is REJECTED LOUDLY', () => {
    const gw1 = gateway(logPath, { clockBase: 0, idBase: 0 });
    gw1.record({ tool_name: 'a', decision: 'PERMITTED', reason: 'ok', request_id: '1' });
    gw1.close();

    const line = readFileSync(logPath, 'utf8').split('\n').filter(Boolean)[0];
    const r = JSON.parse(line);
    r.injected = 'surprise';
    writeFileSync(logPath, JSON.stringify(r) + '\n');

    expect(() => gateway(logPath)).toThrow(ReceiptLogError);
  });

  it('a FOREIGN receipt (validly self-signed under a DIFFERENT key) spliced in is REJECTED LOUDLY', () => {
    const gw1 = gateway(logPath, { clockBase: 0, idBase: 0 });
    gw1.record({ tool_name: 'a', decision: 'PERMITTED', reason: 'ok', request_id: '1' });
    gw1.close();

    // Produce a well-formed receipt under a different key via a separate one-off log, then splice its
    // (validly-self-signed) line onto our chain. Single-key-per-log + chain linkage must reject it.
    const foreignPath = join(dir, 'foreign.jsonl');
    const gwF = gateway(foreignPath, { seed: OTHER_SEED, clockBase: 0, idBase: 0 });
    gwF.record({ tool_name: 'evil', decision: 'PERMITTED', reason: 'x', request_id: '9' });
    gwF.close();
    const foreignLine = readFileSync(foreignPath, 'utf8').split('\n').filter(Boolean)[0];

    appendFileSync(logPath, foreignLine + '\n');
    expect(() => gateway(logPath)).toThrow(ReceiptLogError);
  });

  it('a truncated/partial final line (crash mid-append) is DROPPED and the rest replays + verifies', () => {
    const gw1 = gateway(logPath, { clockBase: 0, idBase: 0 });
    gw1.record({ tool_name: 'a', decision: 'PERMITTED', reason: 'ok', request_id: '1' });
    gw1.record({ tool_name: 'b', decision: 'PERMITTED', reason: 'ok', request_id: '2' });
    gw1.close();

    // Simulate a crash mid-append: a partial JSON fragment with NO trailing newline.
    appendFileSync(logPath, '{"receipt_id":"rcpt-partial","receipt_ver');

    const gw2 = gateway(logPath, { clockBase: 100, idBase: 100 });
    expect(gw2.count).toBe(2); // partial line dropped
    const bundle = gw2.exportBundle();
    expect(verifySepBundle(bundle).verdict).toBe('VERIFIED');

    // The partial remainder was truncated away: a further append lands cleanly and a re-replay works.
    gw2.record({ tool_name: 'c', decision: 'PERMITTED', reason: 'ok', request_id: '3' });
    gw2.close();
    const gw3 = gateway(logPath, { clockBase: 300, idBase: 300 });
    expect(gw3.count).toBe(3);
    expect(verifySepBundle(gw3.exportBundle()).verdict).toBe('VERIFIED');
    gw3.close();
  });

  it('an empty log or a not-yet-created path replays to an empty ledger (not fatal)', () => {
    writeFileSync(logPath, '');
    expect(gateway(logPath).count).toBe(0);
    // A construction pointed at a non-existent path is also fine (nothing to replay yet).
    expect(gateway(join(dir, 'does-not-exist.jsonl')).count).toBe(0);
  });

  it('persistence OFF: NO file is written, and the bundle is byte-identical to the persisted one', () => {
    // Persistence OFF: the gateway is given no path, so nothing should touch the (empty) temp dir.
    const off = gateway(undefined, { clockBase: 0, idBase: 0 });
    off.record({ tool_name: 'a', decision: 'PERMITTED', reason: 'ok', request_id: '1' });
    off.record({ tool_name: 'b', decision: 'DENIED', reason: 'no', request_id: '2' });
    const offBundle = off.exportBundle();
    off.close();
    expect(readdirSync(dir).length).toBe(0); // the OFF gateway wrote no file

    // Persistence ON with identical deterministic inputs -> identical CONTENT (durability only).
    const on = gateway(logPath, { clockBase: 0, idBase: 0 });
    on.record({ tool_name: 'a', decision: 'PERMITTED', reason: 'ok', request_id: '1' });
    on.record({ tool_name: 'b', decision: 'DENIED', reason: 'no', request_id: '2' });
    const onBundle = on.exportBundle();
    on.close();
    expect(readdirSync(dir)).toEqual(['ledger.jsonl']); // the ON gateway wrote exactly the log

    expect(offBundle).toEqual(onBundle);
    expect(verifySepBundle(offBundle).verdict).toBe('VERIFIED');
  });
});
