/**
 * ServerContext: replaces closure pattern in server.ts.
 * Central state container for the AGA MCP Server.
 */
import { generateKeyPair, pkToHex } from './crypto/sign.js';
import { sha256Str } from './crypto/hash.js';
import { Portal } from './core/portal.js';
import { BehavioralMonitor as BehavioralMonitorImpl } from './core/behavioral.js';
import { MemoryStorage } from './storage/memory.js';
import { createGenesisEvent, appendEvent } from './core/chain.js';
import type { AGAStorage } from './storage/interface.js';
import type {
  KeyPair, QuarantineState, ContinuityEvent,
  VerificationTier, ClaimsTaxonomy, DelegationRecord,
  PolicyArtifact, DisclosurePolicy, HashHex,
} from './types.js';
import type { EventType } from './core/types.js';
import type { BehavioralMonitor } from './types.js';

export interface ServerContext {
  issuerKP: KeyPair;
  portalKP: KeyPair;
  chainKP: KeyPair;
  portal: Portal;
  storage: AGAStorage;
  chainInitialized: boolean;
  activeArtifact: PolicyArtifact | null;
  quarantine: QuarantineState | null;
  behavioralMonitor: BehavioralMonitorImpl;
  measurementCount: number;
  verificationTier: VerificationTier;
  startTime: string;
  claimsTaxonomy: ClaimsTaxonomy;
  delegations: DelegationRecord[];
  defaultEnforcement: import('./types.js').EnforcementParams;
  defaultClaims: DisclosurePolicy;
  claimValues: Record<string, unknown>;
  appendToChain(type: EventType, payload: unknown): Promise<ContinuityEvent>;
  json(x: unknown): { content: Array<{ type: 'text'; text: string }> };
  error(msg: string, extra?: Record<string, unknown>): { content: Array<{ type: 'text'; text: string }> };
}

export async function createContext(): Promise<ServerContext> {
  const storage = new MemoryStorage();
  await storage.initialize();

  const issuerKP = generateKeyPair();
  const portalKP = generateKeyPair();
  const chainKP = generateKeyPair();
  const portal = new Portal();
  const behavioralMonitor = new BehavioralMonitorImpl();

  const defaultEnforcement: import('./types.js').EnforcementParams = {
    measurement_cadence_ms: 1000,
    ttl_seconds: 3600,
    enforcement_triggers: ['QUARANTINE', 'TERMINATE'],
    re_attestation_required: true,
    measurement_types: ['FILE_SYSTEM_STATE', 'CONFIG_MANIFEST'],
  };

  const defaultClaims: DisclosurePolicy = {
    claims_taxonomy: [
      // Identity claims
      { claim_id: 'identity.name', sensitivity: 'S3_HIGH', substitutes: ['identity.pseudonym', 'identity.org'], inference_risks: [], permitted_modes: ['PROOF_ONLY'] },
      { claim_id: 'identity.pseudonym', sensitivity: 'S2_MODERATE', substitutes: ['identity.org'], inference_risks: [], permitted_modes: ['PROOF_ONLY', 'REVEAL_MIN'] },
      { claim_id: 'identity.org', sensitivity: 'S1_LOW', substitutes: [], inference_risks: [], permitted_modes: ['PROOF_ONLY', 'REVEAL_MIN', 'REVEAL_FULL'] },
      { claim_id: 'identity.age', sensitivity: 'S3_HIGH', substitutes: ['identity.age_range', 'identity.is_adult'], inference_risks: [], permitted_modes: ['PROOF_ONLY'] },
      { claim_id: 'identity.age_range', sensitivity: 'S2_MODERATE', substitutes: ['identity.is_adult'], inference_risks: [], permitted_modes: ['PROOF_ONLY', 'REVEAL_MIN', 'REVEAL_FULL'] },
      { claim_id: 'identity.is_adult', sensitivity: 'S1_LOW', substitutes: [], inference_risks: [], permitted_modes: ['PROOF_ONLY', 'REVEAL_FULL'] },
      // Vehicle claims (deployment-appropriate)
      { claim_id: 'vehicle.exact_position', sensitivity: 'S4_CRITICAL', substitutes: ['vehicle.grid_square', 'vehicle.operational_area'], inference_risks: [], permitted_modes: ['PROOF_ONLY'] },
      { claim_id: 'vehicle.grid_square', sensitivity: 'S2_MODERATE', substitutes: ['vehicle.operational_area'], inference_risks: [], permitted_modes: ['PROOF_ONLY', 'REVEAL_MIN'] },
      { claim_id: 'vehicle.operational_area', sensitivity: 'S1_LOW', substitutes: [], inference_risks: [], permitted_modes: ['PROOF_ONLY', 'REVEAL_MIN', 'REVEAL_FULL'] },
      // Plant/infrastructure claims
      { claim_id: 'plant.reactor_id', sensitivity: 'S3_HIGH', substitutes: ['plant.facility_type'], inference_risks: [], permitted_modes: ['PROOF_ONLY'] },
      { claim_id: 'plant.facility_type', sensitivity: 'S1_LOW', substitutes: [], inference_risks: [], permitted_modes: ['PROOF_ONLY', 'REVEAL_MIN', 'REVEAL_FULL'] },
      // Agent/model claims
      { claim_id: 'agent.model_weights_hash', sensitivity: 'S4_CRITICAL', substitutes: ['agent.model_family', 'agent.model_generation'], inference_risks: [], permitted_modes: ['PROOF_ONLY'] },
      { claim_id: 'agent.model_family', sensitivity: 'S2_MODERATE', substitutes: ['agent.model_generation'], inference_risks: [], permitted_modes: ['PROOF_ONLY', 'REVEAL_MIN'] },
      { claim_id: 'agent.model_generation', sensitivity: 'S1_LOW', substitutes: [], inference_risks: [], permitted_modes: ['PROOF_ONLY', 'REVEAL_MIN', 'REVEAL_FULL'] },
    ],
    substitution_rules: [],
  };

  const claimValues: Record<string, unknown> = {
    'identity.name': 'Alice Johnson',
    'identity.pseudonym': 'AJ-7742',
    'identity.org': 'Attested Intelligence',
    'identity.age': 32,
    'identity.age_range': '25-34',
    'identity.is_adult': true,
    'vehicle.exact_position': '38.8977° N, 77.0365° W',
    'vehicle.grid_square': 'FM18lv',
    'vehicle.operational_area': 'National Capital Region',
    'plant.reactor_id': 'NRC-R-1234',
    'plant.facility_type': 'Nuclear Power Plant',
    'agent.model_weights_hash': 'a4f8c2e1b3d7094f6e2a8b1c5d9f3e7a',
    'agent.model_family': 'GPT-class LLM',
    'agent.model_generation': 'Generation 4',
  };

  const claimsTaxonomy: ClaimsTaxonomy = {
    claims: defaultClaims.claims_taxonomy,
    version: '1.0.0',
  };

  const ctx: ServerContext = {
    issuerKP,
    portalKP,
    chainKP,
    portal,
    storage,
    chainInitialized: false,
    activeArtifact: null,
    quarantine: null,
    behavioralMonitor,
    measurementCount: 0,
    verificationTier: 'BRONZE',
    startTime: new Date().toISOString(),
    claimsTaxonomy,
    delegations: [],
    defaultEnforcement,
    defaultClaims,
    claimValues,

    async appendToChain(type: EventType, payload: unknown): Promise<ContinuityEvent> {
      if (!ctx.chainInitialized) {
        const genesis = createGenesisEvent(ctx.chainKP, sha256Str('AGA Protocol Specification v2.0.0'));
        await ctx.storage.storeEvent(genesis);
        ctx.chainInitialized = true;
        ctx.portal.sequenceCounter = 0;
        ctx.portal.lastLeafHash = genesis.leaf_hash;
      }
      const prev = await ctx.storage.getLatestEvent();
      if (!prev) throw new Error('Chain initialization failed');
      const event = appendEvent(type, payload, prev, ctx.chainKP);
      await ctx.storage.storeEvent(event);
      ctx.portal.sequenceCounter = event.sequence_number;
      ctx.portal.lastLeafHash = event.leaf_hash;
      return event;
    },

    json(x: unknown) {
      return { content: [{ type: 'text' as const, text: JSON.stringify(x, null, 2) }] };
    },

    error(msg: string, extra?: Record<string, unknown>) {
      return { content: [{ type: 'text' as const, text: JSON.stringify({ success: false, error: msg, ...extra }, null, 2) }] };
    },
  };

  return ctx;
}
