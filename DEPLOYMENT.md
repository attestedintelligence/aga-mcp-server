# AGA MCP Server — Deployment & Hardening Guide

Practical guidance for running `@attested-intelligence/aga-mcp-server` (3.0.1) in a defensible configuration. Scope is the **MCP server boundary** — see `THREAT_BOUNDARY.md` for the full claim/limitation surface this guide operationalizes.

The hardened posture in one line: **stdio upstream + a persisted, well-protected gateway key + network isolation + verifiers that pin the gateway key.**

---

## 1. Upstream mode — stdio (recommended) vs HTTP

The governance proxy (`aga-proxy`) sits between an MCP client and an upstream MCP server and produces a signed receipt for every governed `tools/call`. How you connect the upstream determines whether that mediation can be bypassed.

### ✅ stdio upstream — the hardened default
```bash
npx -p @attested-intelligence/aga-mcp-server aga-proxy start \
  --upstream "npx -y @modelcontextprotocol/server-filesystem /tmp/data" --profile standard
```
The upstream is a **child process** the proxy spawns and talks to over stdio. It is **not network-reachable**, so the agent has no route to the tools except through the proxy. This closes the direct-reach bypass (`THREAT_BOUNDARY.md` §3.1) by construction. **Prefer this mode.**

### ⚠️ HTTP upstream — only behind strict network isolation
```bash
# Bypassable unless the agent CANNOT reach the upstream URL directly.
aga-proxy start --upstream-url "http://127.0.0.1:9000" --profile standard
```
With an HTTP upstream, **anything that can reach the upstream URL bypasses governance entirely** (no receipt). This is a deployment property the server cannot enforce in code. If you must use HTTP upstream:
- Bind the upstream to `127.0.0.1` / a private network the agent cannot reach.
- Use network policy / firewall so the **only** path to the upstream is through the proxy.
- Treat any deployment where the agent can resolve+reach the upstream URL as **ungoverned**.

The server emits an stderr warning when HTTP-upstream mode is used.

### Method coverage
Only `method === "tools/call"` is policy-evaluated. Other JSON-RPC methods are forwarded (with passthrough receipts as of P2; see `THREAT_BOUNDARY.md` §3.2). If your upstream exposes side effects via non-`tools/call` methods, account for that explicitly.

---

## 2. The gateway key — generate, persist, pin, protect

The **gateway key** is the Ed25519 key that signs every receipt and checkpoint. Pinning its public key is what turns a bundle from "internally consistent" into "provably issued by *this* gateway."

### Generate a 32-byte seed (64-hex)
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### Persist it (so provenance survives restarts and is pinnable)
Either:
```bash
export AGA_GATEWAY_KEY=<64-hex-seed>            # environment variable
# or
export AGA_GATEWAY_KEY_FILE=/run/secrets/aga-gateway-key   # file containing the hex seed
```
If neither is set, the server uses an **ephemeral** key that rotates on every restart (it warns on stderr). Ephemeral is fine for local experiments but means **provenance cannot be pinned across restarts** — avoid it in anything you'll later audit.

### Obtain the public key to pin
Call the `get_server_info` tool → **`gateway_public_key`**. That 64-hex value is what verifiers pin.

### Pin it when verifying
```bash
# reference verifier (zero deps)
node aga-receipt-spec/verify/verify-sep.mjs evidence-bundle.json --pubkey <gateway_public_key>
# or the published CLI (@attested-intelligence/aga-verify 2.0.0)
aga-verify evidence-bundle.json --pubkey <gateway_public_key>
```
Or via the tool: `verify_bundle_offline(bundle, pinned_public_key=<gateway_public_key>)`. **Without a pin you get an integrity-only result** (`issuerVerified=false`, summary says "NOT provenance"). See §3.7 of the boundary doc.

### Protect it
The gateway key is a signing secret — **anyone who holds it can mint a fully VERIFIED, provenance-bound bundle saying anything.** Therefore:
- Store it in a secret manager, or a file with restricted permissions (e.g. `chmod 600`, owned by the service user); never world-readable, never committed, never in shell history.
- Rotate by minting a new seed and **re-publishing the new public key** to your verifiers (old bundles stay verifiable against the old key).

---

## 3. Recommended hardened configuration

```jsonc
// Claude Desktop / MCP client config — proxy in front of a stdio upstream, persisted key
{
  "mcpServers": {
    "aga": {
      "command": "npx",
      "args": ["-y", "@attested-intelligence/aga-mcp-server"],
      "env": { "AGA_GATEWAY_KEY_FILE": "/run/secrets/aga-gateway-key" }
    }
  }
}
```
Checklist:
- [ ] stdio upstream (no HTTP upstream, or HTTP only behind network isolation).
- [ ] Persisted gateway key from a secret manager / restricted file.
- [ ] The agent's **only** route to tools is through the proxy (network isolation).
- [ ] Verifiers **pin** `gateway_public_key`; an unpinned PASS is treated as integrity-only, not provenance.
- [ ] Export evidence bundles regularly — default storage is in-memory and the live chain is lost on restart; the **exported, signed bundle is the durable record** (`THREAT_BOUNDARY.md` §3.5).
- [ ] Choose the `restrictive` profile (allowlist, default-deny) for high-stakes upstreams.

---

## 4. Anti-patterns (do not do these)

- ❌ **HTTP upstream without network isolation** — the agent reaches the upstream directly and governance is bypassed (§3.1).
- ❌ **Ephemeral gateway key in production** — provenance can't be pinned across restarts; auditors can't bind bundles to a stable issuer.
- ❌ **Treating an unpinned "VERIFIED" as proof of who issued it** — unpinned is integrity-only (`issuerVerified=false`). Always pin to claim provenance (§3.7).
- ❌ **World-readable / committed / shell-history gateway key** — it's a signing secret; leaking it lets anyone forge provenance-bound bundles.
- ❌ **Relying on the public demo gateway as the canonical artifact** — it's a separate deployment that may track its own version; always verify offline against a pinned key.
- ❌ **Adding a new mutating tool without governing it** — any new agent-action tool must go through the PEP (not `UNGOVERNED_TOOLS`) so it emits a signed receipt (`THREAT_BOUNDARY.md` §2 maintenance invariant).

---

## 5. What this does and does not prove

Per `THREAT_BOUNDARY.md`: a verified bundle proves the **integrity of the receipts present** — authentic, ordered, Merkle-included, checkpoint-bound, and (when pinned) issued by the pinned gateway. It does **not** prove non-omission, prevent jailbreaks, or protect a leaked key. Deployment hardening (this guide) is what makes the in-claim guarantee hold in practice.
