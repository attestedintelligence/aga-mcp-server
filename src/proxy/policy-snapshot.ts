import type { ToolPolicy, ToolConstraint } from './types.js';

function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new Error(`Invalid ${label}`);
  for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(value))) {
    if (!('value' in descriptor)) throw new Error(`Accessors are not accepted in ${label}`);
  }
  return value as Record<string, unknown>;
}
function strings(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 64
    || !value.every(v => typeof v === 'string' && v.length > 0 && v.length <= 4096)) throw new Error(`Invalid ${label}`);
  return [...value];
}
/** Validate, copy and freeze before computing the policy reference. No caller-owned state is retained. */
export function snapshotPolicy(input: ToolPolicy): ToolPolicy {
  const policy = record(input, 'policy');
  if (Object.keys(policy).some(k => !['mode', 'constraints'].includes(k))
    || !['allowlist', 'denylist', 'audit_only'].includes(policy.mode as string)) throw new Error('Invalid policy mode or fields');
  const source = record(policy.constraints, 'constraints');
  if (Object.keys(source).length > 1024) throw new Error('Too many policy constraints');
  const constraints: Record<string, ToolConstraint> = Object.create(null);
  for (const [name, value] of Object.entries(source)) {
    if (!name || name.length > 256) throw new Error('Invalid constraint name');
    const c = record(value, 'constraint');
    if (Object.keys(c).some(k => !['name', 'allowed', 'max_calls_per_minute', 'path_prefix', 'path_keys', 'denied_patterns'].includes(k))
      || c.name !== name || typeof c.allowed !== 'boolean') throw new Error(`Invalid constraint: ${name}`);
    const copy: ToolConstraint = { name, allowed: c.allowed };
    if (c.max_calls_per_minute !== undefined) {
      if (!Number.isSafeInteger(c.max_calls_per_minute) || (c.max_calls_per_minute as number) < 1
        || (c.max_calls_per_minute as number) > 100000) throw new Error('Invalid rate limit');
      copy.max_calls_per_minute = c.max_calls_per_minute as number;
    }
    if (c.path_prefix !== undefined) {
      if (typeof c.path_prefix !== 'string' || !c.path_prefix || c.path_prefix.length > 4096) throw new Error('Invalid path prefix');
      copy.path_prefix = c.path_prefix;
    }
    if (c.path_keys !== undefined) copy.path_keys = Object.freeze(strings(c.path_keys, 'path keys')) as unknown as string[];
    if (c.denied_patterns !== undefined) copy.denied_patterns = Object.freeze(strings(c.denied_patterns, 'denied patterns')) as unknown as string[];
    constraints[name] = Object.freeze(copy);
  }
  return Object.freeze({ mode: policy.mode as ToolPolicy['mode'], constraints: Object.freeze(constraints) });
}
