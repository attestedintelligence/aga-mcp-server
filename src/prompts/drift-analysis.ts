export const DRIFT_ANALYSIS_PROMPT = {
  name: 'drift-analysis',
  description: 'Analyze drift events and recommend remediation',
  arguments: [
    { name: 'drift_type', description: 'Type of drift: binary, behavioral, or both', required: false },
  ],
  template: (args: { drift_type?: string }) => `# Drift Event Analysis

Analyze drift events in the current AGA session for type: ${args.drift_type ?? 'both'}

## Investigation Steps

1. Call \`aga_get_chain\` to retrieve all chain events
2. Filter for INTERACTION_RECEIPT events where drift_detected=true
3. Filter for BEHAVIORAL_DRIFT events
4. Call \`aga_measure_behavior\` for current behavioral state
5. Call \`aga_get_portal_state\` for enforcement status

## Analysis Framework

For each drift event, determine:
- **Root Cause:** Binary modification, prompt injection, configuration change, behavioral anomaly
- **Severity:** Based on enforcement action taken (TERMINATE > QUARANTINE > ALERT_ONLY)
- **Timeline:** When drift was first detected, how many measurements before detection
- **Impact:** Which measurements were affected, what enforcement was applied

## Remediation Recommendations

Based on the drift analysis:
- If binary drift → Recommend re-attestation with updated subject
- If behavioral drift → Recommend baseline adjustment or investigation
- If both → Recommend full security review and incident response

## Output Format

Produce a structured drift analysis report with:
1. Drift event timeline
2. Root cause assessment
3. Severity classification
4. Remediation steps
5. Prevention recommendations`,
};
