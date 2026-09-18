# AGA MCP Server — Deployment & Hardening Guide

Practical guidance for running `@attested-intelligence/aga-mcp-server` (3.x, the current release) in a defensible configuration. Scope is the **MCP server boundary** — see `THREAT_BOUNDARY.md` for the full claim/limitation surface this guide operationalizes.

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

> ### ⚠️ Which entry point are you running? The two do NOT handle the key the same way.
>
> | | `aga-mcp-server` (stdio MCP server) | `aga-proxy` (governance proxy) |
> |---|---|---|
> | Reads `AGA_GATEWAY_KEY` / `AGA_GATEWAY_KEY_FILE` | **yes** | **yes, since 3.6.0** — silently ignored in 3.5.0 and earlier |
> | Key when unset | ephemeral, **warns on stderr** | ephemeral, **warns on stderr** since 3.6.0 (no warning in 3.5.0 and earlier) |
> | Says which key is active at startup | `get_server_info` → `gateway_public_key` | startup banner, since 3.6.0 |
> | Provenance pinnable across restarts | yes, once persisted | yes, once persisted, since 3.6.0 — **no**, at any earlier version |
>
> **If you are on 3.5.0 or earlier:** `aga-proxy` calls `generateSigner()` unconditionally at construction — no key CLI option, no environment variable, no signer through its constructor. Setting `AGA_GATEWAY_KEY` before starting it has **no effect and produces no warning**, and two runs with an identical `AGA_GATEWAY_KEY` produce different gateway public keys. Treat evidence from such a proxy as integrity-verifiable and **not** provenance-pinnable across restarts. Upgrade, or accept that scope.
>
> **From 3.6.0 on** both binaries resolve the key through the same function, in the same order (`AGA_GATEWAY_KEY`, then `AGA_GATEWAY_KEY_FILE`, then ephemeral), with the same warnings. `aga-proxy --ephemeral` makes a throwaway key a stated choice rather than a silent default.
>
> **Pinning is still not automatic, on either binary.** A verifier given a key lifted out of the same bundle it is checking will print `provenance verified` — it cannot know where you got the key. That check is circular. Only a key you obtained **out of band, before** the bundle proves issuance; persisting the key is what makes such a key *exist*, not a substitute for obtaining it independently.
>
> Verified against 3.6.0 (`tests/integration/proxy-gateway-key.test.ts` drives the built `dist/proxy/index.js` in separate processes and asserts one key file yields one public key with zero warnings).

### Generate a 32-byte seed (64-hex)
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### Persist it (so provenance survives restarts and is pinnable) — both binaries, since 3.6.0
Either:
```bash
export AGA_GATEWAY_KEY=<64-hex-seed>            # environment variable
# or
export AGA_GATEWAY_KEY_FILE=/run/secrets/aga-gateway-key   # file containing the hex seed
```
If neither is set, `aga-mcp-server` uses an **ephemeral** key that rotates on every restart (it warns on stderr). Ephemeral is fine for local experiments but means **provenance cannot be pinned across restarts** — avoid it in anything you'll later audit.

`aga-proxy` honours both variables as of **3.6.0**, through the same resolver the MCP server uses, and prints the active public key at startup so you can pin it out of band. Pass `--ephemeral` to deliberately use a throwaway key instead. **In 3.5.0 and earlier the proxy ignored both variables silently** — if you are on an older version, a key you set had no effect and no warning was printed.

### Obtain the public key to pin
For `aga-mcp-server`: call the `get_server_info` tool → **`gateway_public_key`**. That 64-hex value is what verifiers pin.

For `aga-proxy`, since **3.6.0**: the startup banner prints the active public key and where it came from, e.g.

```
Signing gateway key 248acbdb… (persisted via AGA_GATEWAY_KEY_FILE)
```

That line is printed before any bundle exists, which is exactly what makes it usable as an out-of-band pin. Record it from the console or from your process supervisor's log, not from the bundle. `aga-proxy status` still reports only `running` and `pid`.

The gateway key also appears inside the exported bundle (`public_key`) — whether saved to a file or fetched live from the loopback control channel's `GET /export`. **Do not pin that one.** It is the key you are trying to check, so a verifier fed it will agree with itself; and on a proxy left unconfigured (or run with `--ephemeral`) it is a throwaway that rotates on restart. Pinning it proves the bundle is internally consistent — not who issued it.

### Pin it when verifying
```bash
# reference verifier (zero deps)
node aga-receipt-spec/verify/verify-sep.mjs evidence-bundle.json --pubkey <gateway_public_key>
# or the published CLI (ships on npm; renders the identical verdict)
npx -y @attested-intelligence/aga-verify evidence-bundle.json --pubkey <gateway_public_key>
```
Or via the tool: `verify_bundle_offline(bundle, pinned_public_key=<gateway_public_key>)`. **Without a pin you get an integrity-only result** (`issuerVerified=false`, summary says "NOT provenance"). See §3.7 of the boundary doc.

### Protect it
The gateway key is a signing secret — **anyone who holds it can mint a fully VERIFIED, provenance-bound bundle saying anything.** Therefore:
- Store it in a secret manager, or a file with restricted permissions (e.g. `chmod 600`, owned by the service user); never world-readable, never committed, never in shell history.
- Rotate by minting a new seed and **re-publishing the new public key** to your verifiers (old bundles stay verifiable against the old key).

---

## 3. Recommended hardened configuration

```jsonc
// Claude Desktop MCP config — the stdio server with a persisted gateway key.
// (This runs `aga-mcp-server`. For an aga-proxy-in-front-of-upstream deployment see §1;
//  since 3.6.0 the proxy reads the same variable — §2.)
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
- [ ] For a proxy deployment: stdio upstream (no HTTP upstream, or HTTP only behind network isolation).
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
