import type { PolicyArtifact, ContinuityEvent, SignedReceipt, CheckpointReference } from '../core/types.js';

export interface AGAStorage {
  initialize(): Promise<void>;
  close(): Promise<void>;
  storeArtifact(a: PolicyArtifact): Promise<void>;
  getArtifact(sealedHash: string): Promise<PolicyArtifact | null>;
  getLatestArtifact(): Promise<PolicyArtifact | null>;
  storeEvent(e: ContinuityEvent): Promise<void>;
  getEvent(seq: number): Promise<ContinuityEvent | null>;
  getEvents(startSeq: number, endSeq: number): Promise<ContinuityEvent[]>;
  getLatestEvent(): Promise<ContinuityEvent | null>;
  getAllEvents(): Promise<ContinuityEvent[]>;
  storeReceipt(r: SignedReceipt): Promise<void>;
  getReceipt(id: string): Promise<SignedReceipt | null>;
  getReceiptsByArtifact(ref: string): Promise<SignedReceipt[]>;
  getAllReceipts(): Promise<SignedReceipt[]>;
  storeCheckpoint(c: CheckpointReference): Promise<void>;
  getLatestCheckpoint(): Promise<CheckpointReference | null>;
  getCheckpoints(): Promise<CheckpointReference[]>;
}
