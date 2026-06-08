/**
 * Tests for the tool policy evaluator.
 * Ported from aga-mcp-gateway test patterns, extended with rate limiting.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { evaluate, resetRateLimits, cleanPath, matchesPrefix } from '../../src/proxy/evaluator.js';
import type { ToolPolicy } from '../../src/proxy/types.js';

beforeEach(() => {
  resetRateLimits();
});

// ── Path utilities ──────────────────────────────────────────

describe('cleanPath', () => {
  it('normalizes backslashes', () => expect(cleanPath('a\\b\\c')).toBe('a/b/c'));
  it('collapses consecutive slashes', () => expect(cleanPath('a//b///c')).toBe('a/b/c'));
  it('resolves dots', () => expect(cleanPath('/a/./b/../c')).toBe('/a/c'));
  it('handles root', () => expect(cleanPath('/')).toBe('/'));
});

describe('matchesPrefix', () => {
  it('matches exact', () => expect(matchesPrefix('/home', '/home')).toBe(true));
  it('matches child', () => expect(matchesPrefix('/home', '/home/user')).toBe(true));
  it('rejects non-segment match', () => expect(matchesPrefix('/home', '/homelab')).toBe(false));
  it('rejects different path', () => expect(matchesPrefix('/home', '/etc/passwd')).toBe(false));
});

// ── Audit-only mode ─────────────────────────────────────────

describe('audit_only mode', () => {
  const policy: ToolPolicy = { mode: 'audit_only', constraints: {} };

  it('permits any tool', () => {
    const d = evaluate(policy, 'dangerous_tool', { cmd: 'rm -rf /' });
    expect(d.allowed).toBe(true);
    expect(d.reason).toContain('audit_only');
  });
});

// ── Allowlist mode ──────────────────────────────────────────

describe('allowlist mode', () => {
  const policy: ToolPolicy = {
    mode: 'allowlist',
    constraints: {
      filesystem_read: { name: 'filesystem_read', allowed: true },
      filesystem_write: {
        name: 'filesystem_write', allowed: true,
        path_prefix: '/home', path_keys: ['path'],
        denied_patterns: ['/etc/shadow'],
      },
      shell_execute: { name: 'shell_execute', allowed: true, max_calls_per_minute: 3 },
      blocked_tool: { name: 'blocked_tool', allowed: false },
    },
  };

  it('permits listed tool', () => {
    expect(evaluate(policy, 'filesystem_read').allowed).toBe(true);
  });

  it('denies unlisted tool', () => {
    const d = evaluate(policy, 'unknown_tool');
    expect(d.allowed).toBe(false);
    expect(d.reason).toContain('not in allowlist');
  });

  it('denies explicitly disallowed tool', () => {
    const d = evaluate(policy, 'blocked_tool');
    expect(d.allowed).toBe(false);
    expect(d.reason).toContain('explicitly disallowed');
  });

  it('denies path outside prefix', () => {
    const d = evaluate(policy, 'filesystem_write', { path: '/etc/passwd' });
    expect(d.allowed).toBe(false);
    expect(d.reason).toContain('outside allowed prefix');
  });

  it('permits path inside prefix', () => {
    const d = evaluate(policy, 'filesystem_write', { path: '/home/user/file.txt' });
    expect(d.allowed).toBe(true);
  });

  it('denies matching denied pattern', () => {
    const d = evaluate(policy, 'filesystem_write', { path: '/home/user/etc/shadow' });
    // The path is inside prefix but matches denied pattern
    // denied_patterns checks all string values, not just path key
    expect(d.allowed).toBe(false);
    expect(d.reason).toContain('denied pattern');
  });

  it('enforces rate limits', () => {
    expect(evaluate(policy, 'shell_execute').allowed).toBe(true);
    expect(evaluate(policy, 'shell_execute').allowed).toBe(true);
    expect(evaluate(policy, 'shell_execute').allowed).toBe(true);
    // 4th call should be denied
    const d = evaluate(policy, 'shell_execute');
    expect(d.allowed).toBe(false);
    expect(d.reason).toContain('rate limit exceeded');
  });
});

// ── Denylist mode ───────────────────────────────────────────

describe('denylist mode', () => {
  const policy: ToolPolicy = {
    mode: 'denylist',
    constraints: {
      dangerous_tool: { name: 'dangerous_tool', allowed: false },
      rate_limited: { name: 'rate_limited', allowed: true, max_calls_per_minute: 2 },
    },
  };

  it('permits unlisted tool', () => {
    expect(evaluate(policy, 'safe_tool').allowed).toBe(true);
  });

  it('denies listed tool', () => {
    const d = evaluate(policy, 'dangerous_tool');
    expect(d.allowed).toBe(false);
    expect(d.reason).toContain('denied by denylist');
  });

  it('enforces rate limits in denylist mode', () => {
    expect(evaluate(policy, 'rate_limited').allowed).toBe(true);
    expect(evaluate(policy, 'rate_limited').allowed).toBe(true);
    expect(evaluate(policy, 'rate_limited').allowed).toBe(false);
  });
});

// ── Unknown mode ────────────────────────────────────────────

describe('unknown mode', () => {
  it('denies with unknown mode', () => {
    const policy = { mode: 'random' as any, constraints: {} };
    const d = evaluate(policy, 'any_tool');
    expect(d.allowed).toBe(false);
    expect(d.reason).toContain('unknown policy mode');
  });
});
