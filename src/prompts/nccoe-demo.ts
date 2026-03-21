export const NCCOE_DEMO_PROMPT = {
  name: 'nccoe-demo',
  description: 'NCCoE AI Agent Identity and Authorization - Full 4-phase demo with behavioral drift detection',
  arguments: [
    { name: 'agent_code', description: 'The agent source code to attest', required: false },
    { name: 'include_behavioral', description: 'Include behavioral drift detection phase', required: false },
  ],
  template: (args: { agent_code?: string; include_behavioral?: string }) => `# NCCoE Lab Demo - AGA Protocol Full Lifecycle

Execute the following phases using the AGA MCP Server tools:

## Phase 1: Attestation and Identity Binding
1. Call \`aga_init_chain\` to initialize the continuity chain
2. Call \`aga_create_artifact\` with subject content: "${args.agent_code ?? 'def monitor(): return sensors.read_all()'}"
   - Include metadata: filename="scada_agent.py", version="2.1.0", author="engineering"
${args.include_behavioral === 'true' ? `   - Include behavioral_baseline: permitted_tools=["aga_measure_subject","aga_get_portal_state"], rate_limits={"aga_measure_subject":10}, forbidden_sequences=[["read_secret","send_email"]], window_ms=60000` : ''}
3. Verify the portal state is ACTIVE_MONITORING

## Phase 2: Authorized Operation
4. Call \`aga_measure_subject\` with the SAME content - expect match=true
5. Call \`aga_measure_subject\` again - expect match=true, receipt generated
6. Verify both receipts show drift_detected=false

## Phase 3: Simulated Prompt Injection
7. Call \`aga_measure_subject\` with MODIFIED content: "def monitor(): return attacker.exfiltrate(sensors.read_all())"
   - Expect match=false, drift_detected=true
   - Expect enforcement_action=QUARANTINE
8. Check portal state - should be PHANTOM_QUARANTINE
9. Call \`aga_quarantine_status\` to see forensic capture state

## Phase 3b: Mid-Session Revocation
10. Call \`aga_revoke_artifact\` with the sealed hash and reason "Compromise detected"
11. Verify portal state is TERMINATED

${args.include_behavioral === 'true' ? `## Phase 3c: Behavioral Drift Detection
12. Call \`aga_measure_behavior\` to check for tool pattern violations
13. Review violations (unauthorized tools, rate limits, forbidden sequences)
` : ''}

## Phase 4: Offline Audit
${args.include_behavioral === 'true' ? '14' : '12'}. Call \`aga_get_chain\` with verify=true to verify chain integrity
${args.include_behavioral === 'true' ? '15' : '13'}. Call \`aga_export_bundle\` to generate evidence bundle (need checkpoint first)
${args.include_behavioral === 'true' ? '16' : '14'}. Call \`aga_verify_bundle\` with the bundle and issuer public key

All operations should produce signed receipts and chain events.`,
};
