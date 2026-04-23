import type { AGAStorage } from './interface.js';
import type { PolicyArtifact, ContinuityEvent, SignedReceipt, CheckpointReference } from '../core/types.js';

export class MemoryStorage implements AGAStorage {
  private artifacts = new Map<string, PolicyArtifact>();
  private events: ContinuityEvent[] = [];
  private receipts = new Map<string, SignedReceipt>();
  private checkpoints: CheckpointReference[] = [];

  async initialize() {}
  async close() {}
  async storeArtifact(a: PolicyArtifact) { this.artifacts.set(a.sealed_hash, a); }
  async getArtifact(h: string) { return this.artifacts.get(h) ?? null; }
  async getLatestArtifact() { const a = [...this.artifacts.values()]; return a.length ? a[a.length - 1] : null; }
  async storeEvent(e: ContinuityEvent) { this.events.push(e); }
  async getEvent(seq: number) { return this.events.find(e => e.sequence_number === seq) ?? null; }
  async getEvents(s: number, e: number) { return this.events.filter(ev => ev.sequence_number >= s && ev.sequence_number <= e); }
  async getLatestEvent() { return this.events.length ? this.events[this.events.length - 1] : null; }
  async getAllEvents() { return [...this.events]; }
  async storeReceipt(r: SignedReceipt) { this.receipts.set(r.receipt_id, r); }
  async getReceipt(id: string) { return this.receipts.get(id) ?? null; }
  async getReceiptsByArtifact(ref: string) { return [...this.receipts.values()].filter(r => r.artifact_reference === ref); }
  async getAllReceipts() { return [...this.receipts.values()]; }
  async storeCheckpoint(c: CheckpointReference) { this.checkpoints.push(c); }
  async getLatestCheckpoint() { return this.checkpoints.length ? this.checkpoints[this.checkpoints.length - 1] : null; }
  async getCheckpoints() { return [...this.checkpoints]; }
}
