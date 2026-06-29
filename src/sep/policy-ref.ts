// Copyright (c) 2026 Attested Intelligence Holdings LLC
// SPDX-License-Identifier: MIT
import { canonicalize } from './canonical.js';
import { sha256Hex } from './crypto.js';

/**
 * The canonical reference for a policy (or any config object) bound into evidence: the SHA-256 of its
 * canonical form. This is the SINGLE source of the value the governance gateway records as
 * `policy_reference`. The gateway and any external consumer (e.g. the enterprise policy tooling) both call
 * this one function, so the gateway's binding and a consumer's computed reference cannot drift.
 */
export function derivePolicyReference(policy: unknown): string {
  return sha256Hex(canonicalize(policy));
}
