# Tools Directory

All MCP tool handlers are defined inline in `src/server.ts`.
This keeps the server as a single-file reference implementation.

For production use, refactor tools into individual files here:
- attestation-tools.ts (attest_subject)
- enforcement-tools.ts (measure_integrity, revoke_artifact)
- chain-tools.ts (init_chain, verify_chain, get_chain_events)
- checkpoint-tools.ts (create_checkpoint)
- bundle-tools.ts (generate_evidence_bundle, verify_bundle_offline)
- disclosure-tools.ts (request_claim, list_claims)
- portal-tools.ts (get_server_info, get_portal_state, get_receipts)
