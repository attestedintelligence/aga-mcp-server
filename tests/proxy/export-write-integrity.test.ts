import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as fs from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { exportBundleToFile, ExportTargetExistsError } from '../../src/proxy/control.js';

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

  it('keeps old bytes when the final replacement is refused', async () => {
    const output = path.join(dir, 'record.json'); fs.writeFileSync(output, previous);
    vi.spyOn(fs, 'renameSync').mockImplementation(() => { throw ioError('EACCES'); });
    await expect(exportBundleToFile({ proxy, dataDir: dir, output, force: true })).rejects.toMatchObject({ code: 'EACCES' });
    expect(fs.readFileSync(output, 'utf8')).toBe(previous);
    expect(fs.readdirSync(dir)).toEqual(['record.json']);
  });
  it('does not overwrite a destination created by a competing writer at publication', async () => {
    const output = path.join(dir, 'record.json');
    vi.spyOn(fs, 'linkSync').mockImplementation((from, to) => {
      actualFs.writeFileSync(output, previous, { flag: 'wx' });
      return actualFs.linkSync(from, to);
    });
    await expect(exportBundleToFile({ proxy, dataDir: dir, output })).rejects.toBeInstanceOf(ExportTargetExistsError);
    expect(fs.readFileSync(output, 'utf8')).toBe(previous);
    expect(fs.readdirSync(dir)).toEqual(['record.json']);
  });
  it('refuses a filesystem without exclusive link support instead of copying partial bytes', async () => {
    const output = path.join(dir, 'record.json');
    vi.spyOn(fs, 'linkSync').mockImplementation(() => { throw ioError('ENOTSUP'); });
    await expect(exportBundleToFile({ proxy, dataDir: dir, output })).rejects.toMatchObject({ code: 'ENOTSUP' });
    expect(fs.existsSync(output)).toBe(false);
    expect(fs.readdirSync(dir)).toEqual([]);
  });
  it('replaces one directory entry without modifying other hard links to the old file', async () => {
    const output = path.join(dir, 'record.json'), retained = path.join(dir, 'retained.json');
    fs.writeFileSync(retained, previous); fs.linkSync(retained, output);
    await exportBundleToFile({ proxy, dataDir: dir, output, force: true });
    expect(fs.readFileSync(retained, 'utf8')).toBe(previous);
    expect(JSON.parse(fs.readFileSync(output, 'utf8'))).toEqual(proxy.exportBundle());
    expect(fs.readdirSync(dir).sort()).toEqual(['record.json', 'retained.json']);
  });
  it.skipIf(process.platform === 'win32')('replaces a symlink itself instead of truncating its referent', async () => {
    const output = path.join(dir, 'record.json'), retained = path.join(dir, 'retained.json');
    fs.writeFileSync(retained, previous); fs.symlinkSync(retained, output);
    await expect(exportBundleToFile({ proxy, dataDir: dir, output })).rejects.toBeInstanceOf(ExportTargetExistsError);
    await exportBundleToFile({ proxy, dataDir: dir, output, force: true });
    expect(fs.readFileSync(retained, 'utf8')).toBe(previous);
    expect(fs.lstatSync(output).isSymbolicLink()).toBe(false);
    expect(JSON.parse(fs.readFileSync(output, 'utf8'))).toEqual(proxy.exportBundle());
  });
  it.skipIf(process.platform === 'win32')('creates a private file on POSIX systems', async () => {
    const output = path.join(dir, 'record.json');
    await exportBundleToFile({ proxy, dataDir: dir, output });
    expect(fs.statSync(output).mode & 0o777).toBe(0o600);
  });
  it('reports cleanup failure without turning a completed publication into a failed export', async () => {
    const output = path.join(dir, 'record.json');
    vi.spyOn(fs, 'rmdirSync').mockImplementation(() => { throw ioError('EACCES'); });
    const warning = vi.spyOn(process, 'emitWarning').mockImplementation(() => {});
    await expect(exportBundleToFile({ proxy, dataDir: dir, output })).resolves.toMatchObject({ receiptCount: 1 });
    expect(JSON.parse(fs.readFileSync(output, 'utf8'))).toEqual(proxy.exportBundle());
    expect(warning).toHaveBeenCalledWith(expect.stringContaining('staging cleanup'), { code: 'AGA_EXPORT_CLEANUP' });
  });
});
