/**
 * Performance test - 1 test.
 * Ensures measurement cycle stays under 10ms (NIST target).
 */
import { describe, it, expect } from 'vitest';
import { createContext } from '../../src/context.js';
import { handleCreateArtifact } from '../../src/tools/create-artifact.js';
import { handleMeasureSubject } from '../../src/tools/measure-subject.js';

describe('performance - NIST <10ms target', () => {
  it('measurement cycle completes under 10ms average', async () => {
    const ctx = await createContext();
    await handleCreateArtifact({ subject_content: 'perf-test-code', subject_metadata: { filename: 'perf.py' } }, ctx);

    const iterations = 20;
    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      await handleMeasureSubject({ subject_content: 'perf-test-code', subject_metadata: { filename: 'perf.py' } }, ctx);
    }
    const elapsed = performance.now() - start;
    const avgMs = elapsed / iterations;

    expect(avgMs).toBeLessThan(10); // NIST target: <10ms per cycle
  });
});
