import * as fs from 'node:fs';
import * as path from 'node:path';

/** Publish complete bytes without truncating an existing destination during preparation.
 * This requires ordinary same-filesystem link/rename semantics. It is not a
 * power-loss, network-filesystem or hostile shared-directory durability guarantee.
 */
export function writeExportFile(output: string, data: string, force: boolean): void {
  const target = path.resolve(output);
  const staging = fs.mkdtempSync(path.join(path.dirname(target), '.aga-export-'));
  const temporary = path.join(staging, 'bundle.json');
  let fd: number | undefined;
  try {
    fd = fs.openSync(temporary, 'wx', 0o600);
    fs.writeFileSync(fd, data, 'utf8');
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    if (force) fs.renameSync(temporary, target);
    else fs.linkSync(temporary, target); // Atomic exclusive publication; EEXIST never truncates.
  } finally {
    // Do not turn a completed publication into a misleading failure, or mask the
    // original write error. Cleanup touches only the file and directory we created.
    let cleanupFailed = false;
    if (fd !== undefined) { try { fs.closeSync(fd); } catch { cleanupFailed = true; } }
    try { fs.unlinkSync(temporary); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') cleanupFailed = true; }
    try { fs.rmdirSync(staging); } catch { cleanupFailed = true; }
    if (cleanupFailed) process.emitWarning('Export staging cleanup was incomplete. Inspect the adjacent .aga-export-* directory; do not treat it as a second export.', { code: 'AGA_EXPORT_CLEANUP' });
  }
}
