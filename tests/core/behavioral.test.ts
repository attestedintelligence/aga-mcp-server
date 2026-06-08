import { describe, it, expect } from 'vitest';
import { BehavioralMonitor } from '../../src/core/behavioral.js';
import { sha256Str } from '../../src/crypto/hash.js';

describe('behavioral drift detection', () => {
  it('no violations with compliant behavior', () => {
    const m = new BehavioralMonitor();
    m.setBaseline({
      permitted_tools: ['read_sensor', 'log_status'],
      rate_limits: { read_sensor: 10 },
      forbidden_sequences: [],
      window_ms: 60000,
    });
    m.recordInvocation('read_sensor', sha256Str('{}'));
    m.recordInvocation('log_status', sha256Str('{}'));
    const result = m.measure();
    expect(result.drift_detected).toBe(false);
    expect(result.violations).toHaveLength(0);
  });

  it('detects unauthorized tool', () => {
    const m = new BehavioralMonitor();
    m.setBaseline({
      permitted_tools: ['read_sensor'],
      rate_limits: {},
      forbidden_sequences: [],
      window_ms: 60000,
    });
    m.recordInvocation('delete_database', sha256Str('{}'));
    const result = m.measure();
    expect(result.drift_detected).toBe(true);
    expect(result.violations[0].type).toBe('UNAUTHORIZED_TOOL');
  });

  it('detects rate limit exceeded', () => {
    const m = new BehavioralMonitor();
    m.setBaseline({
      permitted_tools: ['read_sensor'],
      rate_limits: { read_sensor: 3 },
      forbidden_sequences: [],
      window_ms: 60000,
    });
    for (let i = 0; i < 5; i++) m.recordInvocation('read_sensor', sha256Str(`${i}`));
    const result = m.measure();
    expect(result.drift_detected).toBe(true);
    expect(result.violations.some(v => v.type === 'RATE_EXCEEDED')).toBe(true);
  });

  it('detects forbidden sequence', () => {
    const m = new BehavioralMonitor();
    m.setBaseline({
      permitted_tools: ['read_secret', 'send_email'],
      rate_limits: {},
      forbidden_sequences: [['read_secret', 'send_email']],
      window_ms: 60000,
    });
    m.recordInvocation('read_secret', sha256Str('{}'));
    m.recordInvocation('send_email', sha256Str('{}'));
    const result = m.measure();
    expect(result.drift_detected).toBe(true);
    expect(result.violations.some(v => v.type === 'FORBIDDEN_SEQUENCE')).toBe(true);
  });

  it('behavioral hash changes with different patterns', () => {
    const m1 = new BehavioralMonitor();
    m1.setBaseline({ permitted_tools: ['a', 'b'], rate_limits: {}, forbidden_sequences: [], window_ms: 60000 });
    m1.recordInvocation('a', sha256Str('1'));

    const m2 = new BehavioralMonitor();
    m2.setBaseline({ permitted_tools: ['a', 'b'], rate_limits: {}, forbidden_sequences: [], window_ms: 60000 });
    m2.recordInvocation('b', sha256Str('1'));

    expect(m1.measure().behavioral_hash).not.toBe(m2.measure().behavioral_hash);
  });
});
