/**
 * Disclosure tool tests - 5 tests.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { createContext, type ServerContext } from '../../src/context.js';
import { handleCreateArtifact } from '../../src/tools/create-artifact.js';
import { handleDiscloseClaim } from '../../src/tools/disclose-claim.js';

function parse(result: { content: Array<{ type: string; text: string }> }) {
  return JSON.parse(result.content[0].text);
}

describe('disclosure tool - 5 tests', () => {
  let ctx: ServerContext;
  beforeEach(async () => {
    ctx = await createContext();
    // Create artifact to enable governed tools
    await handleCreateArtifact({ subject_content: 'code', subject_metadata: { filename: 'f.py' } }, ctx);
  });

  it('discloses S1_LOW claim with REVEAL_FULL', async () => {
    const r = parse(await handleDiscloseClaim({ claim_id: 'identity.org', mode: 'REVEAL_FULL' }, ctx));
    expect(r.success).toBe(true);
    expect(r.permitted).toBe(true);
    expect(r.disclosed_value).toBe('Attested Intelligence');
  });

  it('auto-substitutes S3_HIGH claim on REVEAL_MIN', async () => {
    const r = parse(await handleDiscloseClaim({ claim_id: 'identity.name', mode: 'REVEAL_MIN' }, ctx));
    expect(r.success).toBe(true);
    expect(r.was_substituted).toBe(true);
    expect(r.disclosed_claim_id).toBe('identity.pseudonym');
  });

  it('allows PROOF_ONLY for S3_HIGH claim', async () => {
    const r = parse(await handleDiscloseClaim({ claim_id: 'identity.name', mode: 'PROOF_ONLY' }, ctx));
    expect(r.success).toBe(true);
    expect(r.permitted).toBe(true);
    expect(r.was_substituted).toBe(false);
    expect(r.disclosed_value).toBe(true); // proof only = boolean
  });

  it('rejects unknown claim', async () => {
    const r = parse(await handleDiscloseClaim({ claim_id: 'nonexistent.claim' }, ctx));
    expect(r.success).toBe(true); // tool succeeds, but disclosure is not permitted
    expect(r.permitted).toBe(false);
  });

  it('substitution generates chain event', async () => {
    await handleDiscloseClaim({ claim_id: 'identity.name', mode: 'REVEAL_MIN' }, ctx);
    const events = await ctx.storage.getAllEvents();
    const subEvents = events.filter(e => e.event_type === 'SUBSTITUTION');
    expect(subEvents.length).toBeGreaterThan(0);
  });
});
