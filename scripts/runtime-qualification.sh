#!/usr/bin/env bash
set -euo pipefail
node --version
mkdir /tmp/subject
(cd /subject && tar --exclude=node_modules -cf - src tests fixtures scripts dist aga-receipt-spec package.json package-lock.json vitest.config.ts tsconfig.json) | tar -xf - -C /tmp/subject
ln -s /subject/node_modules /tmp/subject/node_modules
cd /tmp/subject
node /subject/node_modules/vitest/vitest.mjs run --no-cache --maxWorkers=1 --no-file-parallelism
node fixtures/run-conformance.mjs
