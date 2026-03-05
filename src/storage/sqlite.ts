import type { AGAStorage } from './interface.js';
import type { PolicyArtifact, ContinuityEvent, SignedReceipt, CheckpointReference } from '../core/types.js';

// Dynamic import — better-sqlite3 is optional (requires native build tools)
let Database: any;
try {
  Database = (await import('better-sqlite3')).default;
} catch {
  // Will throw at construction time if better-sqlite3 is not available
}

export class SQLiteStorage implements AGAStorage {
  private db: any;
  constructor(path = 'aga.sqlite') {
    if (!Database) throw new Error('better-sqlite3 is not installed. Install Visual Studio Build Tools and run: npm install better-sqlite3');
    this.db = new Database(path);
    this.db.pragma('journal_mode = WAL');
  }
  async initialize() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS artifacts (sealed_hash TEXT PRIMARY KEY, data TEXT NOT NULL, created_at TEXT DEFAULT (datetime('now')));
      CREATE TABLE IF NOT EXISTS chain_events (sequence_number INTEGER PRIMARY KEY, event_id TEXT UNIQUE, event_type TEXT, leaf_hash TEXT, data TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS receipts (receipt_id TEXT PRIMARY KEY, artifact_reference TEXT, sequence_number INTEGER, data TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS checkpoints (id INTEGER PRIMARY KEY AUTOINCREMENT, merkle_root TEXT, batch_start INTEGER, batch_end INTEGER, data TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS idx_receipts_artifact ON receipts(artifact_reference);
    `);
  }
  async close() { this.db.close(); }
  private p<T>(row: any): T | null { return row ? JSON.parse(row.data) : null; }
  async storeArtifact(a: PolicyArtifact) { this.db.prepare('INSERT OR REPLACE INTO artifacts (sealed_hash,data) VALUES (?,?)').run(a.sealed_hash, JSON.stringify(a)); }
  async getArtifact(h: string) { return this.p<PolicyArtifact>(this.db.prepare('SELECT data FROM artifacts WHERE sealed_hash=?').get(h)); }
  async getLatestArtifact() { return this.p<PolicyArtifact>(this.db.prepare('SELECT data FROM artifacts ORDER BY created_at DESC LIMIT 1').get()); }
  async storeEvent(e: ContinuityEvent) { this.db.prepare('INSERT INTO chain_events (sequence_number,event_id,event_type,leaf_hash,data) VALUES (?,?,?,?,?)').run(e.sequence_number, e.event_id, e.event_type, e.leaf_hash, JSON.stringify(e)); }
  async getEvent(seq: number) { return this.p<ContinuityEvent>(this.db.prepare('SELECT data FROM chain_events WHERE sequence_number=?').get(seq)); }
  async getEvents(s: number, e: number) { return (this.db.prepare('SELECT data FROM chain_events WHERE sequence_number>=? AND sequence_number<=? ORDER BY sequence_number').all(s, e) as any[]).map((r: any) => JSON.parse(r.data)); }
  async getLatestEvent() { return this.p<ContinuityEvent>(this.db.prepare('SELECT data FROM chain_events ORDER BY sequence_number DESC LIMIT 1').get()); }
  async getAllEvents() { return (this.db.prepare('SELECT data FROM chain_events ORDER BY sequence_number').all() as any[]).map((r: any) => JSON.parse(r.data)); }
  async storeReceipt(r: SignedReceipt) { this.db.prepare('INSERT INTO receipts (receipt_id,artifact_reference,sequence_number,data) VALUES (?,?,?,?)').run(r.receipt_id, r.artifact_reference, r.sequence_number, JSON.stringify(r)); }
  async getReceipt(id: string) { return this.p<SignedReceipt>(this.db.prepare('SELECT data FROM receipts WHERE receipt_id=?').get(id)); }
  async getReceiptsByArtifact(ref: string) { return (this.db.prepare('SELECT data FROM receipts WHERE artifact_reference=? ORDER BY sequence_number').all(ref) as any[]).map((r: any) => JSON.parse(r.data)); }
  async getAllReceipts() { return (this.db.prepare('SELECT data FROM receipts ORDER BY sequence_number').all() as any[]).map((r: any) => JSON.parse(r.data)); }
  async storeCheckpoint(c: CheckpointReference) { this.db.prepare('INSERT INTO checkpoints (merkle_root,batch_start,batch_end,data) VALUES (?,?,?,?)').run(c.merkle_root, c.batch_start_sequence, c.batch_end_sequence, JSON.stringify(c)); }
  async getLatestCheckpoint() { return this.p<CheckpointReference>(this.db.prepare('SELECT data FROM checkpoints ORDER BY id DESC LIMIT 1').get()); }
  async getCheckpoints() { return (this.db.prepare('SELECT data FROM checkpoints ORDER BY id').all() as any[]).map((r: any) => JSON.parse(r.data)); }
}
