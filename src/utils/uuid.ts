import { randomUUID } from 'node:crypto';

/** RFC 4122 v4 UUID via node:crypto (CSPRNG-backed; no external dependency). */
export function uuid(): string { return randomUUID(); }
