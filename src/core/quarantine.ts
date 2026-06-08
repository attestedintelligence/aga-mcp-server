import { utcNow } from '../utils/timestamp.js';
import type { QuarantineState } from './types.js';

export function initQuarantine(): QuarantineState {
  return { active: true, started_at: utcNow(), inputs_captured: 0, outputs_severed: true, forensic_buffer: [] };
}

export function captureInput(q: QuarantineState, inputType: string, data: unknown): void {
  q.forensic_buffer.push({ timestamp: utcNow(), type: inputType, data });
  q.inputs_captured++;
}

export function releaseQuarantine(q: QuarantineState): { duration_ms: number; total_captures: number } {
  q.active = false;
  return { duration_ms: q.started_at ? Date.now() - Date.parse(q.started_at) : 0, total_captures: q.inputs_captured };
}
