import { verifyChainIntegrity } from '../core/chain.js';
import type { ServerContext } from '../context.js';

export interface GetChainArgs {
  start_seq?: number;
  end_seq?: number;
  verify?: boolean;
  filter_type?: string;
}

const FILTER_MAP: Record<string, string[]> = {
  behavioral: ['BEHAVIORAL_DRIFT'],
  delegations: ['DELEGATION'],
  receipts: ['INTERACTION_RECEIPT'],
  revocations: ['REVOCATION'],
  attestations: ['POLICY_ISSUANCE', 'RE_ATTESTATION', 'ATTESTATION'],
  disclosure: ['DISCLOSURE', 'SUBSTITUTION'],
  keys: ['KEY_ROTATION'],
};

export async function handleGetChain(args: GetChainArgs, ctx: ServerContext) {
  let events = (args.start_seq !== undefined && args.end_seq !== undefined)
    ? await ctx.storage.getEvents(args.start_seq, args.end_seq)
    : await ctx.storage.getAllEvents();

  // Apply filter_type
  if (args.filter_type && args.filter_type !== 'all') {
    const allowedTypes = FILTER_MAP[args.filter_type];
    if (allowedTypes) {
      events = events.filter(e => allowedTypes.includes(e.event_type));
    }
  }

  const result: Record<string, unknown> = {
    count: events.length,
    events: events.map(e => ({
      sequence_number: e.sequence_number,
      event_type: e.event_type,
      event_id: e.event_id,
      timestamp: e.timestamp,
      leaf_hash: e.leaf_hash.slice(0, 16) + '...',
      previous_leaf_hash: e.previous_leaf_hash ? e.previous_leaf_hash.slice(0, 16) + '...' : null,
      payload_hash: e.payload_hash.slice(0, 16) + '...',
    })),
  };

  if (args.verify) {
    const allEvents = await ctx.storage.getAllEvents();
    const integrity = verifyChainIntegrity(allEvents);
    result.chain_valid = integrity.valid;
    result.broken_at = integrity.brokenAt;
    result.verification_error = integrity.error;
    result.leaf_hash_formula = 'SHA-256(schema_version || protocol_version || event_type || event_id || sequence_number || timestamp || previous_leaf_hash) - PAYLOAD EXCLUDED';
    result.event_signature_covers = 'COMPLETE event including payload';
  }

  return ctx.json(result);
}
