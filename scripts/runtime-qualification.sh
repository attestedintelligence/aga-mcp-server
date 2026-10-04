#!/usr/bin/env bash
set -euo pipefail
node --version
mkdir /tmp/subject
(cd /subject && tar --exclude=node_modules -cf - .) | tar -xf - -C /tmp/subject
ln -s /subject/node_modules /tmp/subject/node_modules
cd /tmp/subject
node /subject/node_modules/vitest/vitest.mjs run --no-cache --maxWorkers=1 --no-file-parallelism --reporter=default --reporter=json --outputFile.json=/evidence/tests.json
node fixtures/run-conformance.mjs
node --test scripts/runtime-release-evidence.test.mjs
node scripts/consumer-qualification.mjs
AGA_DISPOSABLE_CHECK=1 node scripts/benchmark-export-proofs.mjs
