/**
 * Behavioral tool tests - 4 tests.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { createContext, type ServerContext } from '../../src/context.js';
import { handleCreateArtifact } from '../../src/tools/create-artifact.js';
import { handleMeasureBehavior } from '../../src/tools/measure-behavior.js';

function parse(result: { content: Array<{ type: string; text: string }> }) {
  return JSON.parse(result.content[0].text);
}

describe('behavioral tool - 4 tests', () => {
  let ctx: ServerContext;
  beforeEach(async () => { ctx = await createContext(); });

  it('no violations without baseline', async () => {
    const r = parse(await handleMeasureBehavior({} as any, ctx));
    expect(r.success).toBe(true);
    expect(r.drift_detected).toBe(false);
    expect(r.violation_count).toBe(0);
  });

  it('detects unauthorized tool with baseline', async () => {
    await handleCreateArtifact({
      subject_content: 'code',
      subject_metadata: { filename: 'f.py' },
      behavioral_baseline: {
        permitted_tools: ['aga_measure_subject'],
        rate_limits: {},
        forbidden_sequences: [],
        window_ms: 60000,
      },
    }, ctx);
    // Record an unauthorized tool invocation
    ctx.behavioralMonitor.recordInvocation('unauthorized_tool', 'hash123');
    const r = parse(await handleMeasureBehavior({} as any, ctx));
    expect(r.success).toBe(true);
    expect(r.drift_detected).toBe(true);
    expect(r.violations.some((v: any) => v.type === 'UNAUTHORIZED_TOOL')).toBe(true);
  });

  it('detects rate limit exceeded', async () => {
    await handleCreateArtifact({
      subject_content: 'code',
      subject_metadata: { filename: 'f.py' },
      behavioral_baseline: {
        permitted_tools: ['aga_measure_subject'],
        rate_limits: { 'aga_measure_subject': 2 },
        forbidden_sequences: [],
        window_ms: 60000,
      },
    }, ctx);
    ctx.behavioralMonitor.recordInvocation('aga_measure_subject', 'h1');
    ctx.behavioralMonitor.recordInvocation('aga_measure_subject', 'h2');
    ctx.behavioralMonitor.recordInvocation('aga_measure_subject', 'h3');
    const r = parse(await handleMeasureBehavior({} as any, ctx));
    expect(r.drift_detected).toBe(true);
    expect(r.violations.some((v: any) => v.type === 'RATE_EXCEEDED')).toBe(true);
  });

  it('behavioral drift appends chain event', async () => {
    await handleCreateArtifact({
      subject_content: 'code',
      subject_metadata: { filename: 'f.py' },
      behavioral_baseline: {
        permitted_tools: ['allowed_only'],
        rate_limits: {},
        forbidden_sequences: [],
        window_ms: 60000,
      },
    }, ctx);
    ctx.behavioralMonitor.recordInvocation('bad_tool', 'hash');
    await handleMeasureBehavior({} as any, ctx);
    const events = await ctx.storage.getAllEvents();
    const driftEvents = events.filter(e => e.event_type === 'BEHAVIORAL_DRIFT');
    expect(driftEvents.length).toBeGreaterThan(0);
  });
});
