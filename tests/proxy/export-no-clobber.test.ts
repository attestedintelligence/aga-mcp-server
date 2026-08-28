/**
 * RC9-06 regression guard — `export --output` must never destroy an operator's file.
 *
 * The defect: exportBundleToFile called fs.writeFileSync unconditionally, so pointing
 * `--output` at an EXISTING file silently truncated it and exited 0 reporting success.
 * No attacker, no unusual deployment, no symlink — an ordinary path, on the exact artifact
 * a verifier consumes. Founder ruling D-21.7 (exclusive-create default, replacement opt-in)
 * was made and never implemented.
 *
 * These tests assert on the BYTES of the pre-existing file, not merely on a thrown error —
 * a guard that throws after truncating would still have destroyed the data.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { exportBundleToFile, ExportTargetExistsError } from '../../src/proxy/control.js';

const PRECIOUS = '{"operator":"do not destroy me","key":"secret-material"}\n';

/** Stub in-process proxy so the export resolves without a live control channel. */
const stubProxy = { exportBundle: () => ({ receipts: [{ receipt_id: 'r1' }], checkpoint: {} }) };

describe('RC9-06: export --output must not clobber an existing file', () => {
  let dir: string;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'aga-rc906-')); });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  it('refuses an existing destination and leaves its bytes BYTE-IDENTICAL', async () => {
    const target = join(dir, 'precious.json');
    writeFileSync(target, PRECIOUS);

    await expect(
      exportBundleToFile({ proxy: stubProxy, dataDir: dir, output: target })
    ).rejects.toBeInstanceOf(ExportTargetExistsError);

    // THE ASSERTION THAT MATTERS: the operator's data is still there, untouched.
    expect(readFileSync(target, 'utf8')).toBe(PRECIOUS);
  });

  it('writes normally to a fresh path (control — the guard must not break the happy path)', async () => {
    const target = join(dir, 'new-bundle.json');
    const res = await exportBundleToFile({ proxy: stubProxy, dataDir: dir, output: target });

    expect(res.receiptCount).toBe(1);
    expect(existsSync(target)).toBe(true);
    expect(JSON.parse(readFileSync(target, 'utf8')).receipts).toHaveLength(1);
  });

  it('replaces an existing file ONLY when --force is passed explicitly', async () => {
    const target = join(dir, 'precious.json');
    writeFileSync(target, PRECIOUS);

    const res = await exportBundleToFile({ proxy: stubProxy, dataDir: dir, output: target, force: true });

    expect(res.receiptCount).toBe(1);
    const after = readFileSync(target, 'utf8');
    expect(after).not.toBe(PRECIOUS);              // deliberate replacement did happen
    expect(JSON.parse(after).receipts).toHaveLength(1);
  });
});
