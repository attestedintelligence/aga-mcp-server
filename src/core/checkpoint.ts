import { buildMerkleTree, inclusionProof } from '../crypto/merkle.js';
import { utcNow } from '../utils/timestamp.js';
import { uuid } from '../utils/uuid.js';
import type { ContinuityEvent, CheckpointReference, AnchorBatchPayload } from './types.js';
import type { MerkleInclusionProof } from '../crypto/types.js';

export function createCheckpoint(events: ContinuityEvent[], anchorNetwork = 'local'): { checkpoint: CheckpointReference; payload: AnchorBatchPayload } {
  if (!events.length) throw new Error('No events to checkpoint');
  const { root } = buildMerkleTree(events.map(e => e.leaf_hash));
  const checkpoint: CheckpointReference = {
    merkle_root: root, batch_start_sequence: events[0].sequence_number,
    batch_end_sequence: events[events.length - 1].sequence_number,
    anchor_network: anchorNetwork, transaction_id: `${anchorNetwork}:${uuid()}`, timestamp: utcNow(),
  };
  return { checkpoint, payload: { checkpoint_reference: checkpoint, leaf_count: events.length } };
}

export function eventInclusionProof(events: ContinuityEvent[], targetSeq: number): MerkleInclusionProof {
  const idx = events.findIndex(e => e.sequence_number === targetSeq);
  if (idx === -1) throw new Error(`Sequence ${targetSeq} not in batch`);
  return inclusionProof(events.map(e => e.leaf_hash), idx);
}
