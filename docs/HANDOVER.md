# ngrid-lab — Handover Note

**Project:** ngrid-lab — intentionally-vulnerable API lab
**Course:** CCISONFI Advanced VAPT · Mod 1 (Advanced API Exploitation & NIBSS Integration)
**Updated:** 2026-11-27 · maintainer: David George

---

## 1. What this is
A multi-tier, deliberately-vulnerable fintech API used to teach advanced API exploitation:

```
client ──▶ edge-proxy (:8088, deny rules / "WAF", CL.TE-smugglable)
        ──▶ gateway-app (Spring Boot, :8080 internal, trusts X-Internal-Caller)
        ──▶ Postgres ledger (no row locks)
```

## 2. Decision locked in (2026-11-27)
Moved the lab from a "cheat-sheet UI" (labelled buttons/toggles that handed students each exploit) to a **realistic banking portal**. Students now find and run everything through Burp, like a real target.

**Teaching scope = full advanced chain (5 topics):**
`JWT → BOLA → SQLi → request smuggling → internal-settlement drain`

## 3. Code changes made this session
- **Frontend** `gateway-app/src/main/resources/static/index.html` — rebuilt as a believable Ngrid retail-banking portal (sign in · your accounts · transfer · recent activity). Removed ALL scaffolding: Recon-extras buttons, `spoof X-Internal-Caller` + `send Bearer token` toggles, Internal/admin card with pre-filled drain payload, "Look up by ID (BOLA)" label + all-accounts dump, Dev-mode request logger, Burp-hint footer. 16.5 KB → 8.9 KB. **Original saved as `index.html.orig`.**
- **Backend** `controller/AuthController.java` — removed the `"hint"` fields from `/api/auth/login` and `/api/auth/service-token` responses (the API no longer narrates its own flaws; vulnerable behaviour unchanged).
- **No exploit code was removed.** Every planted vuln is still live — the cleanup only took away the training wheels.

## 4. Build & run
Maven builds inside the image, so no local build needed:
```
docker compose build gateway-app && docker compose up -d gateway-app
```
- Portal (through edge-proxy): `http://<host>:8088`
- Login: any username mints that user's token — **no password check** (see §7). Use `alice`.
- Reset the ledger between runs (unauthenticated): `curl -X POST http://<host>:8088/reset`

**Seed accounts** (`db/init.sql`, balances in minor units):
`1001 alice NGN 2,500,000` · `1002 bob NGN 180,000` · `1003 carol USD 90,000` · `9001 internal-system NGN 999,999,999`

## 5. The five exploits (Burp-first, no UI aids)
1. **Broken Auth / JWT** — `Authorization: Bearer`. `alg:none` accepted; HS256 verified against weak secret `secret`; RS256→HS256 confusion (public key at `GET /api/auth/pubkey`). Forge `role:ADMIN` / `sub:bob`. Code: `security/VulnerableJwtFilter.java`.
2. **BOLA / IDOR** — `GET /api/accounts/{id}` and `/{id}/transfers`, no ownership check. Enumerate `1001 → 1002 → 9001`. Code: `controller/TransferController.java`.
3. **SQL injection** — `GET /api/accounts?owner=` (LIKE concatenation; UNION target table `api_keys`) and `/accounts/{id}` (id concatenation). The portal's own login call exposes the `owner` param in Burp. Code: `service/LedgerService.java`.
4. **HTTP request smuggling** — edge-proxy CL.TE desync past the `/internal` deny rule. Code: `edge-proxy/smuggle_proxy.py`; reference exploit `scripts/exploits/smuggle_waf_bypass.py`.
5. **Internal-settlement drain** — smuggled `POST /internal/settlement/batch` carrying `X-Internal-Caller: true` (the JWT filter trusts it → ADMIN) drains account `9001`. Code: `controller/InternalSettlementController.java`.

**Present but out of taught scope** (left in backend, unadvertised): TOCTOU double-spend (`LedgerService.transferWithBalanceCheck`, 150 ms race window); SSRF + prompt injection + key leak (`controller/AiAssistantController.java` → `/api/assistant/fetch|summarize|config`).

**Secrets to exfiltrate:** `api_keys` table → `settlement-signer: sk_lab_7f3c9a2e_do_not_reuse`, `reporting-readonly: sk_lab_11b4_report_only`; assistant upstream key `sk-lab-UPSTREAM-9f2c7a41d0e84b6`; JWT HMAC secret `secret`. (All lab-only dummy values.)

## 6. Run-order for the live session
Recon (read Burp history on login) → JWT forge → BOLA enumerate → SQLi dump `api_keys` → smuggle past the proxy → drain `9001`. Each link feeds the next (the chain, not any single bug, is the headline).

## 7. Known issues / watch-outs
- **Login accepts ANY password** (no user store). A sharp pentester clocks it fast. Optional fix: add a users table + password check (~10–15 min). **Not yet done.**
- **Smuggling is the least reliable hop live.** Script exact Burp steps: intercept, turn OFF "Update Content-Length", use the precise CL.TE body. This is the most likely "why isn't it working" moment.
- **Discovery of `/internal` + `X-Internal-Caller` is now instructor-led** (hint buttons removed) — demo the discovery, students replay.
- **Exposure:** the box was reachable on a public IP (redacted here — this repo is public; keep the address in a private note). Before the session, lock it to the training LAN/VPN/allowlist — it is deliberately vulnerable.

## 8. Remaining work (TODO)
1. Rebuild and verify all 5 exploits on the cleaned lab.
2. Realign the **step-through deck** (Canva `DAHcA9W1yI0`) and the **practice guide** (Claude Doc) from the old 6-hop flow to this 5-topic chain, Burp-first.
3. Write bulletproof smuggling run-steps into the facilitator notes.
4. (Optional) add real password auth.
5. (Pre-session) lock down network exposure.

## 9. Key files
- `edge-proxy/smuggle_proxy.py`
- `gateway-app/src/main/java/ng/ccisonfi/nibbslab/controller/*.java`
- `gateway-app/src/main/java/ng/ccisonfi/nibbslab/security/VulnerableJwtFilter.java`
- `gateway-app/src/main/java/ng/ccisonfi/nibbslab/service/LedgerService.java`
- `gateway-app/src/main/resources/static/index.html` (+ `index.html.orig` backup)
- `db/init.sql` (seed data)
- `scripts/exploits/` (`jwt_attacks.sh`, `sqli_dump_keys.sh`, `smuggle_waf_bypass.py`, `toctou_double_spend.sh`)
- `docs/` (`MOD1_DEEPDIVE_LAB.md`, `MOD1_FACILITATION_GUIDE.md`, `LAB_FINDINGS.md`, this note)
