// Build the publishable CLI: bundle verify.ts -> dist/aga-verify.mjs with a
// POSIX shebang. Uses the esbuild JS API so the shebang is a literal JS string
// (avoids shell/MSYS path translation of "/usr/bin/env").
import { build } from 'esbuild';

await build({
  entryPoints: ['verify.ts'],
  bundle: true,
  platform: 'node',
  format: 'esm',
  packages: 'external', // keep @noble/* as runtime deps, do not inline
  banner: { js: '#!/usr/bin/env node' },
  outfile: 'dist/aga-verify.mjs',
});

console.log('built dist/aga-verify.mjs');
