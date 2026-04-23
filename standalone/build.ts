/**
 * Build script - produces aga-demo.exe (or .bat fallback)
 *
 * Attested Intelligence Holdings LLC
 */
import { execSync } from 'node:child_process';
import {
  writeFileSync, copyFileSync, existsSync, mkdirSync, unlinkSync
} from 'node:fs';
import { resolve } from 'node:path';

const OUT = resolve('dist-standalone');
const BUNDLE = resolve(OUT, 'aga-demo.cjs');
const SEA_CONFIG = resolve(OUT, 'sea-config.json');
const SEA_BLOB = resolve(OUT, 'sea-prep.blob');
const EXE = resolve(OUT, 'aga-demo.exe');

if (!existsSync(OUT)) mkdirSync(OUT, { recursive: true });

console.log('');
console.log('╔═══════════════════════════════════════════════╗');
console.log('║  AGA Standalone v2 - Build                    ║');
console.log('║  Attested Intelligence Holdings LLC           ║');
console.log('╚═══════════════════════════════════════════════╝');
console.log('');

// Step 1: Bundle
console.log('[1/4] Bundling with esbuild (TypeScript → CJS)...');
execSync([
  'npx esbuild standalone/main.ts',
  '--bundle',
  '--platform=node',
  '--format=cjs',
  '--target=node20',
  `--outfile=${BUNDLE}`,
  '--external:better-sqlite3',
  '--external:@anduril-industries/lattice-sdk',
].join(' '), { stdio: 'inherit' });

// Step 2: SEA config
console.log('\n[2/4] SEA configuration...');
writeFileSync(SEA_CONFIG, JSON.stringify({
  main: BUNDLE, output: SEA_BLOB,
  disableExperimentalSEAWarning: true, useCodeCache: true,
}, null, 2));

// Step 3: SEA blob
console.log('\n[3/4] Generating SEA blob...');
let usedSea = false;
try {
  execSync(`node --build-sea ${SEA_CONFIG}`, { stdio: 'inherit' });
  usedSea = true;
} catch {
  try {
    execSync(`node --experimental-sea-config ${SEA_CONFIG}`, { stdio: 'inherit' });
    usedSea = true;
  } catch {
    console.log('  SEA generation failed - using fallback build.');
  }
}

if (usedSea) {
  // Step 4: Create exe
  console.log('\n[4/4] Creating executable...');
  copyFileSync(process.execPath, EXE);
  try { execSync(`signtool remove /s "${EXE}"`, { stdio: 'pipe' }); } catch {}
  execSync([
    'npx postject', `"${EXE}"`, 'NODE_SEA_BLOB', `"${SEA_BLOB}"`,
    '--sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2',
  ].join(' '), { stdio: 'inherit' });

  for (const f of [SEA_BLOB, SEA_CONFIG]) { try { unlinkSync(f); } catch {} }
  // Keep bundle for child process spawning
  console.log(`\n  ✓ Built: ${EXE}`);
} else {
  // Fallback: bundle + node.exe + bat
  console.log('\n[FALLBACK] Creating bundle + launcher...');
  const nodeExe = resolve(OUT, 'node.exe');
  copyFileSync(process.execPath, nodeExe);
  const bat = resolve(OUT, 'aga-demo.bat');
  writeFileSync(bat, '@echo off\r\n"%~dp0node.exe" "%~dp0aga-demo.cjs" %*\r\n');
  for (const f of [SEA_BLOB, SEA_CONFIG]) { try { unlinkSync(f); } catch {} }
  console.log(`\n  ✓ Built: ${bat}`);
  console.log('  Distribution: zip dist-standalone/ folder');
}

console.log('\n  Run: aga-demo.exe');
console.log('  Run: aga-demo.exe --scenario=scada');
console.log('  Run: aga-demo.exe --scenario=all --non-interactive');
console.log('  Run: aga-demo.exe --watch path/to/file.py');
console.log('');
