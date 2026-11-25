# nibbs-api-lab

A small, **intentionally vulnerable** API stack for practicing web/API security
testing locally. It mimics a bank-style "edge proxy + gateway + ledger DB" shape
so you can drill fund-transfer / settlement attacks against something realistic.

> ⚠️ **Training use only.** Everything here is insecure *by design*. Keep it on
> your own machine (ports bind to `127.0.0.1`), never deploy it anywhere
> reachable, and don't point tooling built here at any real system. The
> `ng.ccisonfi.nibbslab` package name is a lab theme — this is **not** NIBSS code
> and talks to nothing but its own throwaway Postgres container.

## Stack

| Component     | What it is                                   | Port (localhost) |
|---------------|----------------------------------------------|------------------|
| `edge-proxy`  | Purpose-built vulnerable HTTP proxy (smuggling) | `8088`        |
| `gateway-app` | Spring Boot 3.3 / Java 17 API (embedded Tomcat) | internal 8080 |
| `db`          | Postgres 16 with a seeded ledger             | `5432`           |

## Run it

```bash
cd nibbs-api-lab
docker compose up --build
```

Everything goes through the edge proxy at `http://127.0.0.1:8088`.

```bash
# alg:none forges an identity with no signature (planted bug):
TOKEN="$(printf '{"alg":"none"}' | basenc --base64url | tr -d '=').$(printf '{"sub":"alice","role":"USER"}' | basenc --base64url | tr -d '=')."
curl -s http://127.0.0.1:8088/api/accounts/1001 -H "Authorization: Bearer $TOKEN"
```

Verified exploit scripts live in `scripts/exploits/` (all default to `BASE`/host
`127.0.0.1:8088`):

```bash
scripts/exploits/jwt_attacks.sh            # alg:none, weak-secret, RS256->HS256 confusion
scripts/exploits/sqli_dump_keys.sh         # UNION-dump api_keys
scripts/exploits/toctou_double_spend.sh    # concurrent-transfer double-spend
python3 scripts/exploits/smuggle_waf_bypass.py   # request smuggling + chunked WAF bypass
curl -X POST http://127.0.0.1:8088/reset   # restore ledger balances
```

## Planted issues (the exercise set)

**JWT auth — `security/VulnerableJwtFilter.java`, `controller/AuthController.java`**
- `alg:none` tokens are accepted (no signature).
- HS256 is verified against a weak secret (`secret`) — crackable offline
  (`jwt_tool`, `hashcat -m 16500`) then forgeable. `POST /api/auth/login` hands
  out a weakly-signed token to capture.
- **RS256 → HS256 algorithm confusion**: the public key is published at
  `GET /api/auth/pubkey`; the HS256 path also accepts a signature made with that
  public key, so you can forge an ADMIN token. `POST /api/auth/service-token`
  issues a genuine RS256 token.
- No `exp`/`iss`/`aud` checks. `X-Internal-Caller: true` is an instant-ADMIN
  header bypass.

**Access control & money movement — `TransferController`, `InternalSettlementController`**
- BOLA/IDOR: `GET /api/accounts/{id}` returns any account.
- **TOCTOU double-spend** (`LedgerService.transferWithBalanceCheck`): balance is
  read, then there's a `Thread.sleep(150)` window, then the debit — no row lock,
  no serializable isolation. Concurrent requests all pass the same check.
- `/internal/settlement/batch` moves money in bulk behind only the spoofable role.

**Injection — `LedgerService`**
- SQL injection via string-concatenated queries; `api_keys` is a UNION target.

**Request smuggling / WAF bypass — `edge-proxy/smuggle_proxy.py`**
- The edge frames requests by **Content-Length only** and ignores
  **Transfer-Encoding**, then naively splices trailing bytes through. Tomcat
  honors chunked, so a pipelined request hidden after a `0\r\n\r\n` chunk is run
  by the backend but never seen by the edge WAF (which blocks `/internal` and
  `X-Internal-Caller`). The smuggled response poisons the next client.
- *Why a custom proxy and not nginx/HAProxy?* Modern nginx/HAProxy buffer and
  re-frame bodies, normalizing the desync away, and this Tomcat (10.1.x) rejects
  the dual CL+TE and header-obfuscation vectors outright (verified). A purpose-
  built naive proxy reproduces the primitive deterministically against the real
  Spring backend.

**AI/LLM endpoint — `AiAssistantController`**
- SSRF: `POST /api/assistant/fetch` fetches any URL server-side (reaches
  `/internal`, the DB host, metadata).
- Prompt injection + **API key leakage**: the upstream key sits in the system
  preamble that untrusted document text can exfiltrate via
  `POST /api/assistant/summarize`; `GET /api/assistant/config` also over-shares it.

**Config / exposure**
- Full stack traces to clients; all actuator endpoints open (`/actuator/*`).
- Weak hardcoded DB password and JWT secret; containers run as root.

## Reset hook

`POST /reset` wipes transfers and restores seed balances so a seat can be re-run
after double-spend / injection exercises. Unauthenticated on purpose (lab convenience).

## Provisioning many seats

`scripts/provision.sh` launches isolated instances, each its own compose project
with a private network; only the edge is published, on a per-seat loopback port.

```bash
scripts/provision.sh up 200 9000   # seats on 127.0.0.1:9001 .. 127.0.0.1:9200
scripts/provision.sh list
scripts/provision.sh down 200 9000
```

Images are built once and reused, so 200 seats spin up without rebuilding.

## Suggested flow

1. Map the surface (`/actuator/*`, error leakage, `/api/auth/pubkey`).
2. Break auth: `alg:none`, crack the weak HS256 secret, RS256→HS256 confusion.
3. Access control: IDOR, then the TOCTOU double-spend.
4. SQLi → dump `api_keys`.
5. Smuggle past the edge WAF to reach `/internal`; SSRF from the assistant.
6. For each: write the fix and re-test.
