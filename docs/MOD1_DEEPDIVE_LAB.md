# Mod 1 — Deep-Knowledge Lab (Advanced, Half-Day)

**Audience:** VAPT practitioners who have already seen the Mod 1 concept session (or equivalent).
**Length:** 3.5 hours, hands-on.
**Posture of the room:** everyone on their own seat, keyboards hot the whole time. This is not a demo
session — the facilitator sets each objective, the room works it, and we regroup on the *why* and the *fix*.

> This session trades breadth for depth. The concept session proves each bug exists in isolation.
> This one does three things the concept session does not:
> 1. **Root-cause teardown** — for each class, *why* the code is exploitable at the line level, and the
>    full spectrum of fixes (not just "add a check").
> 2. **One chained kill-chain** — recon → cracked auth → SQLi → stolen key → smuggle past the WAF →
>    `/internal` settlement. Isolated bugs don't get budget; a chain to money movement does.
> 3. **Write-the-fix-and-retest** — participants patch, rebuild, and prove the exploit now fails. A
>    finding you can't close is half a finding.

All of it runs against the lab you already have. Nothing below needs new code — every command here was
verified against the live stack on `127.0.0.1:8088`.

---

## 0. Facilitator pre-flight (do this before the room arrives)

```bash
cd /Users/davidgeorge/StudioProjects/lab/nibbs-api-lab
docker compose up -d --build
# smoke test — expect HTTP/1.1 200 and a weakly-signed token
curl -s -X POST http://127.0.0.1:8088/api/auth/login \
     -H 'Content-Type: application/json' -d '{"username":"alice"}' | head -c 200; echo
curl -s -X POST http://127.0.0.1:8088/reset        # clean ledger
```

Dry-run all four exploit scripts once so you've seen today's output with today's container build:

```bash
scripts/exploits/jwt_attacks.sh
scripts/exploits/sqli_dump_keys.sh
scripts/exploits/toctou_double_spend.sh ; curl -s -X POST http://127.0.0.1:8088/reset
python3 scripts/exploits/smuggle_waf_bypass.py
```

**Known environment gotchas (from build-out):**
- Colima/Docker on macOS: if `:8088` won't bind, `docker compose down` then up; a stale Colima SSH
  forward can squat a port.
- Host `5432`/`8080` clashes: the stack is self-contained on the Docker network — don't run a second
  local Postgres or a host-side gateway alongside it.
- Cold start: the gateway takes a few seconds after `up`. A `502`/`000` in the first ~5s is boot, not a
  bug. Re-run once.
- The **smuggle poison is timing-sensitive** and occasionally needs a second run (the script says
  `not poisoned (retry once)` and exits non-zero). Know this *before* you run it live — it's the LIFO
  connection pool, not a broken lab. See Block 4.

Reset between any destructive exercise with `curl -X POST http://127.0.0.1:8088/reset`.

---

## 1. Framing (15 min)

Open on the architecture, drawn on the board, because every attack today is about a **disagreement
between two components**:

```
client ─▶ edge-proxy (WAF + framing) ─▶ gateway-app (Spring/Tomcat) ─▶ Postgres ledger
            └ frames by Content-Length        └ honors Transfer-Encoding      └ no row locks
              inspects line+headers only         trusts X-Internal-Caller
```

The thesis for the day: **real breaches at a settlement switch are rarely one exotic bug. They are a
boring misconfiguration that lets you in, chained to a logic flaw that moves money.** We will build
exactly that chain.

Map to the frameworks they're being certified against (one slide, keep it quick):

| Lab vuln | OWASP API Top 10 (2023) | CBN RBCSF theme |
|---|---|---|
| alg:none / weak-HMAC / RS256→HS256 | API2 Broken Auth | Access control & cryptography |
| IDOR on `/api/accounts/{id}` | API1 BOLA | Authorization |
| TOCTOU double-spend | API6 / business-logic | Transaction integrity |
| SQLi → `api_keys` | API8 + injection | Data protection |
| Request smuggling / WAF bypass | API8 misconfig + network | Perimeter / segmentation |
| SSRF + prompt-injection key leak | API7 SSRF / LLM01 | Third-party & AI risk |

---

## 2. Block A — Auth teardown: the whole JWT story (45 min)

**Objective for the room:** forge an ADMIN identity three different ways, and understand why each works
at the line level.

### Run it
```bash
scripts/exploits/jwt_attacks.sh     # alg:none, weak-secret crack, RS256→HS256 confusion
```

### Teardown — read `security/VulnerableJwtFilter.java` together
Three independent failures, each a real-world pattern:

1. **`alg:none` accepted.** The filter branches on the header's `alg` and, for `none`, skips signature
   verification entirely. Root cause: *the token tells the verifier how to verify it.* The attacker
   controls the header, so the attacker controls the trust decision.
   ```bash
   TOKEN="$(printf '{"alg":"none"}' | basenc --base64url | tr -d '=').$(printf '{"sub":"alice","role":"ADMIN"}' | basenc --base64url | tr -d '=')."
   curl -s http://127.0.0.1:8088/api/accounts/1001 -H "Authorization: Bearer $TOKEN"
   ```

2. **Weak HMAC secret (`secret`).** `POST /api/auth/login` hands out a real HS256 token. Offline:
   `hashcat -m 16500 token.txt wordlist` or `jwt_tool`. Once cracked, every token is forgeable. Root
   cause: *a signature only means something if the key is unguessable.*

3. **RS256 → HS256 algorithm confusion.** The public key is published at `GET /api/auth/pubkey`. The
   HS256 verification path accepts a MAC computed with **the public key bytes as the HMAC secret**. The
   server treats the public key as public *for verification* but as secret *for signing* — the classic
   confusion. Forge an ADMIN token signed with the public key, send it as HS256.

Plus the two freebies: **no `exp`/`iss`/`aud` checks** (tokens never expire, no audience binding) and
**`X-Internal-Caller: true` → instant ADMIN** (a header backdoor left in "for internal calls").

### Write the fix (participants, 15 min)
Have them specify the corrected filter, not just hand-wave it:
- **Pin the algorithm server-side.** Don't read `alg` from the token to choose the verifier — the server
  decides RS256, full stop. Reject `none`.
- **Verify with the public key only** on the RS256 path; never accept an HMAC on an endpoint that issues
  RS256. Separate the two key types so a public key can never be an HMAC secret.
- **Rotate to a high-entropy secret** if HS256 is kept at all; treat `secret` as compromised.
- **Enforce `exp`, `iss`, `aud`.** Short TTL + refresh.
- **Delete the `X-Internal-Caller` bypass.** Internal trust comes from network position / mTLS, never a
  spoofable client header.

Discussion hook: *which of these would a scanner have caught?* (alg:none and missing-exp, maybe. The
RS256→HS256 confusion and the header backdoor are logic — they need a human. That's the whole argument
for VAPT over a scan.)

---

## 3. Block B — Business logic: TOCTOU, deeply (45 min)

**Objective:** drive an account negative by racing concurrent transfers, then reason about *every* layer
that could have stopped it.

### Run it
```bash
curl -s -X POST http://127.0.0.1:8088/reset
scripts/exploits/toctou_double_spend.sh
# bob's balance goes negative — the check passed N times on the same stale read
curl -s -X POST http://127.0.0.1:8088/reset
```

### Teardown — `service/LedgerService.transferWithBalanceCheck`
The window, line by line:
```
read balance            ← time of CHECK
Thread.sleep(150)       ← the race window (explicit here; in prod it's just I/O latency)
debit                   ← time of USE
```
No row lock, no serializable isolation, no idempotency key. Ten concurrent requests all read the same
balance, all pass the check, all debit. The `sleep` only makes a real, latency-sized window *reliable*
for teaching — the bug is the unprotected read-then-write, not the sleep.

**Why this is the headline for a settlement switch:** this is the bug a scanner cannot find and a code
review often misses. It's not a payload — it's *timing*. In a real NIBSS-style flow it's double-spend,
duplicate settlement, or balance underflow. This is the slot to spend your energy on.

### The fix spectrum (whiteboard, then they pick one and implement)
Four defensible answers — make them argue the trade-offs:
1. **Pessimistic lock** — `SELECT ... FOR UPDATE` on the row inside the transaction. Simple, correct,
   serializes that account.
2. **Atomic conditional update** — `UPDATE accounts SET balance = balance - :amt WHERE id = :id AND
   balance >= :amt`; check affected-rows. No read-then-write gap at all.
3. **Serializable isolation** — let the DB abort the losers; requires retry logic.
4. **Idempotency key** — a client-supplied key stored unique, so a replay/duplicate is a no-op. Solves
   duplicate-submission, which is the sibling problem.

Best practitioners will say "2 *and* 4" — atomic debit for the race, idempotency for the replay. That's
the production answer.

### Retest
Implement option 2 in `LedgerService`, `docker compose up -d --build gateway-app`, rerun the script,
show bob bottoms out at `0` not negative. **That's** the deliverable: exploit → fix → proof.

---

## ☕ Break (10 min)

---

## 4. Block C — The chain (50 min)  ← the centrepiece

Stop doing bugs in isolation. Build one narrative from "unauthenticated outsider" to "I moved settlement
money," each step feeding the next. This is what a finding in a report to management actually looks like.

**Step 1 — Recon the misconfiguration.** Actuator is wide open.
```bash
curl -s http://127.0.0.1:8088/actuator/env | head -c 400; echo
curl -s http://127.0.0.1:8088/actuator/mappings | head -c 400; echo
```
Note the leaked surface and stack traces. *Entry point: we didn't even need creds to map the app.*

**Step 2 — Break auth** (from Block A) — forge a token so the account endpoints answer.

**Step 3 — SQLi to steal the upstream API key.**
```bash
scripts/exploits/sqli_dump_keys.sh
# UNION dumps api_keys.secret into the owner_sub text column; also leaks PG version
```
Root cause: string-concatenated SQL in `LedgerService`. Fix: parameterized queries / bound statements —
and note the UNION only worked once column *types* lined up (teach the bigint-vs-text alignment; it's a
real part of exploit dev, not a footnote).

**Step 4 — The WAF stands between us and `/internal`.** Prove it blocks us directly:
```bash
curl -s http://127.0.0.1:8088/internal/settlement/health      # → 403 WAF blocked (edge)
```

**Step 5 — Smuggle past it.**
```bash
python3 scripts/exploits/smuggle_waf_bypass.py
# victim's normal request comes back poisoned with {"role":"ADMIN","internal":true,"ok":true}
```
The smuggled `GET /internal/...` carrying `X-Internal-Caller: true` is executed by Tomcat but never seen
by the edge WAF. We reached the internal settlement surface the perimeter was supposed to protect.

**Debrief the chain as a story:** *open actuator (API8) told us the shape → forged JWT (API2) got us
authenticated → SQLi (injection) handed us a real credential → request smuggling (API8/network) walked
that past the WAF to the money-movement endpoint.* No single bug here is a catastrophe. The **chain** is
the catastrophe — and the fix is defence-in-depth, because closing any one link breaks it.

---

## 5. Block D — Proxy internals & the smuggling primitive (40 min)

This is the "deep knowledge" block the concept session deliberately skips. Practitioners going deep want
to know *why the smuggle is deterministic here when it's flaky in the wild*. Open
`edge-proxy/smuggle_proxy.py` and walk it.

### The desync, precisely
- The proxy **frames every request by `Content-Length` and ignores `Transfer-Encoding`** (`handle_client`
  → `_content_length`, TE never consulted). The Tomcat backend **honors chunked**. That disagreement is
  the entire primitive.
- The outer request is `Transfer-Encoding: chunked` with a `0\r\n\r\n` body. The proxy counts **zero**
  body bytes by CL, so everything after it — the pipelined `GET /internal/...` — is treated as opaque
  trailing bytes and **spliced straight through, unseen by the WAF** (`handle_client` reads the request
  line + headers only; `WAF_BLOCK_PATH_TOKENS` / `WAF_BLOCK_HEADER_TOKENS` never touch the body).
- Tomcat parses the chunked body (empty), then parses the *next* bytes as a **second pipelined request**
  and runs it. Its response is queued on that upstream connection.

### Why it's deterministic here (the honest part)
Say this out loud — VAPT pros respect it:
> Modern nginx/HAProxy buffer and re-frame request bodies, normalizing this disagreement away, and this
> Tomcat (10.1.x) *rejects* the textbook dual `CL+TE` and header-obfuscation vectors outright (verified).
> So a stock proxy won't reliably reproduce the desync in a self-contained lab. This edge is a
> **purpose-built naive proxy** that reproduces the classic primitive on demand. We teach the *primitive*,
> not this proxy's code.

And the reason the **poisoning** is reliable, not random — the **LIFO connection pool** (`_checkout`/
`_checkin`, `POOL_SIZE=16`, `threading.Condition`):
- Concurrent requests get **distinct** upstream connections → the backend's TOCTOU race is reachable
  *through* the proxy (a single shared connection would serialize requests and kill the race — that was
  a real bug during build-out).
- A **just-used** connection is handed to the **very next** request (last-in-first-out) → the queued,
  smuggled response lands on a chosen victim deterministically instead of whoever happens to poll next.

That one data structure is why *both* the race (Block B) and the smuggle poison (Block C) work reliably
in the same rig. Good "aha" to land.

### If the poison misses
The script prints `not poisoned (retry once)` and exits non-zero — that's the pool state, not a failure.
Run it again. Use the miss as the teaching moment: in the wild, smuggling *is* probabilistic; you fire
repeatedly and win on connection reuse.

### Fixes
- Frame on a **single** canonical interpretation; reject messages with both CL and TE, or with
  ambiguous/duplicate CL (RFC 7230 §3.3.3). Prefer a proxy that re-frames bodies.
- WAF must parse the **same** message model as the backend, or it inspects a different request than the
  one that runs.
- Terminate and re-originate connections; don't blindly pool and splice.

---

## 6. Block E — AI / SSRF surface & the key leak (20 min)

```bash
curl -s -X POST http://127.0.0.1:8088/api/assistant/fetch \
     -H 'Content-Type: application/json' \
     -d '{"url":"http://localhost:8080/actuator/env"}' | head -c 300; echo
curl -s http://127.0.0.1:8088/api/assistant/config          # leaks upstreamApiKey sk-lab-UPSTREAM-...
```
- **SSRF** (`/api/assistant/fetch`) fetches any URL server-side — it reaches the gateway's own actuator,
  the DB host, cloud metadata. Note the honest caveat: `/actuator/env` **masks** secret values (`******`)
  because Spring sanitizes known-sensitive keys, so SSRF proves *reach*, not the raw secret.
- **The raw credential leaks two other ways:** `/api/assistant/config` over-shares it, and the
  **prompt-injection** path (`/api/assistant/summarize`) puts the upstream key in the system preamble, so
  untrusted document text can instruct the model to echo it back (LLM01). Order the demo: SSRF for reach →
  `/config` + injection for the actual key.
- Fixes: allowlist egress for the fetcher (no internal ranges/metadata), never put secrets in a prompt,
  strip secrets from any config endpoint, treat document text as untrusted.

---

## 7. Wrap & fix-retest consolidation (15 min)

Go round the room: **each participant names one vuln they patched and shows the exploit now failing.**
That's the muscle this session is building — not "I found it" but "I closed it and proved it closed."

Close on the chain slide again and the one sentence worth leaving them with:
> *The perimeter, the auth layer, the data layer and the AI layer each had one flaw. Any single fix
> breaks the chain to money. Defence-in-depth isn't belt-and-braces — it's the business case.*

Feeds directly into the Day-3 live-fire capstone (`scripts/provision.sh up 100 9000` → one isolated seat
per participant, capture-flags, scored "how + fix" writeups) and the Day-4 exec post-mortem (the fixes
they wrote here are the Track-1 bridge).

---

## Appendix — timing at a glance

| Block | Topic | Min |
|---|---|---|
| Framing | Architecture + framework map | 15 |
| A | JWT teardown + write-the-fix | 45 |
| B | TOCTOU deep + fix spectrum + retest | 45 |
| — | Break | 10 |
| C | The chain (recon→auth→SQLi→smuggle→/internal) | 50 |
| D | Proxy internals & smuggling primitive | 40 |
| E | AI/SSRF surface + key leak | 20 |
| Wrap | Fix-retest round + capstone hand-off | 15 |
| | **Total** | **~3h30** |

All commands verified against the live stack on `127.0.0.1:8088`. Reset with
`curl -X POST http://127.0.0.1:8088/reset` between destructive blocks.
