export const GOVERNANCE_REPORT_PROMPT = {
  name: 'governance-report',
  description: 'Generate a session governance summary report',
  arguments: [],
  template: () => `# Session Governance Summary Report

Generate a comprehensive governance report for the current AGA session:

1. Call \`aga_server_info\` for server identity and key information
2. Call \`aga_get_portal_state\` for current enforcement status
3. Call \`aga_get_chain\` with verify=true for chain integrity
4. Call \`aga_measure_behavior\` for behavioral analysis
5. Call \`aga_quarantine_status\` for quarantine state

Then produce a report with:
- **Session Identity:** Server keys, verification tier, uptime
- **Governance State:** Portal state, artifact status, TTL remaining
- **Chain Integrity:** Event count, verification status, any breaks
- **Behavioral Analysis:** Violations detected, behavioral hash
- **Quarantine Status:** Active/inactive, forensic captures
- **Measurement Summary:** Total measurements, drift events
- **Compliance Status:** NIST/NCCoE alignment assessment

Format as a structured markdown report suitable for audit documentation.`,
};
