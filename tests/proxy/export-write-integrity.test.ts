import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as fs from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { exportBundleToFile } from '../../src/proxy/control.js';

// Intercept the named ESM bindings used by control.ts, not only fs.default.
vi.mock('node:fs', async importOriginal => {
  const actual = await importOriginal<typeof import('node:fs')>();
  return { ...actual, writeFileSync: vi.fn(actual.writeFileSync), fsyncSync: vi.fn(actual.fsyncSync) };
});
const actualFs = await vi.importActual<typeof import('node:fs')>('node:fs');

const previous = '{"retained":"synthetic prior evidence"}\n';
const proxy = { exportBundle: () => ({ receipts: [{ receipt_id: 'synthetic' }], checkpoint: {} }) };
let dir: string;
beforeEach(() => {
  vi.mocked(fs.writeFileSync).mockImplementation(actualFs.writeFileSync);
  vi.mocked(fs.fsyncSync).mockImplementation(actualFs.fsyncSync);
  dir = fs.mkdtempSync(path.join(tmpdir(), 'aga-export-integrity-'));
});
afterEach(() => {
  vi.restoreAllMocks(); vi.clearAllMocks();
  const resolved = path.resolve(dir);
  if (path.dirname(resolved) !== path.resolve(tmpdir()) || !path.basename(resolved).startsWith('aga-export-integrity-')) throw new Error('Refusing unsafe test cleanup');
  fs.rmSync(resolved, { recursive: true, force: true });
});
const ioError = (code: string) => Object.assign(new Error('Synthetic ' + code), { code });
function failAfterPartialWrite() {
  vi.mocked(fs.writeFileSync).mockImplementation(((file, _data, options) => {
    actualFs.writeFileSync(file, '{"partial":', options);
    throw ioError('ENOSPC');
  }) as typeof fs.writeFileSync);
}

describe('export disk failure preserves retained evidence', () => {
  it('keeps the old destination byte-identical when a forced write runs out of space', async () => {
    const output = path.join(dir, 'record.json'); fs.writeFileSync(output, previous);
    failAfterPartialWrite();
    await expect(exportBundleToFile({ proxy, dataDir: dir, output, force: true })).rejects.toMatchObject({ code: 'ENOSPC' });
    expect(fs.readFileSync(output, 'utf8')).toBe(previous);
    expect(fs.readdirSync(dir)).toEqual(['record.json']);
  });
  it('does not leave a partial destination after a fresh write fails', async () => {
    const output = path.join(dir, 'record.json'); failAfterPartialWrite();
    await expect(exportBundleToFile({ proxy, dataDir: dir, output })).rejects.toMatchObject({ code: 'ENOSPC' });
    expect(fs.existsSync(output)).toBe(false);
    expect(fs.readdirSync(dir)).toEqual([]);
  });
  it('does not replace retained evidence when flushing the staged file fails', async () => {
    const output = path.join(dir, 'record.json'); fs.writeFileSync(output, previous);
    vi.mocked(fs.fsyncSync).mockImplementation(() => { throw ioError('EIO'); });
    await expect(exportBundleToFile({ proxy, dataDir: dir, output, force: true })).rejects.toMatchObject({ code: 'EIO' });
    expect(fs.readFileSync(output, 'utf8')).toBe(previous);
    expect(fs.readdirSync(dir)).toEqual(['record.json']);
  });
});
