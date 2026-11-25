# Instructor Guide and Answer Key (do not distribute)

## Run order
1. `scripts/package.sh`, then `terraform apply` (see README). Wait about 10 minutes for bootstrap (`BOOTSTRAP-COMPLETE` in `/var/log/lab-bootstrap.log`).
2. Smoke test on the instructor host: open `http://127.0.0.1:8001`, Dial, press 1. Expect a balance with `[EVID-S2-…]` (vulnerable profile).
3. Class: theory blocks A to E, then scenarios 1 to 10 in the **vulnerable** profile, then a validation phase.
4. Validation phase: on each team host run `sudo /opt/lab/scripts/labctl.sh mode secure`; participants retest. Switch back with `mode vulnerable`.
5. Between sessions: `sudo /opt/lab/scripts/labctl.sh reset` (re-seeds all data, clears PIN budgets and logs). Per participant: `reset 4`.

Profiles are per participant container, so one participant's reset or toggle never affects another. Each team host is a separate instance.

## Evidence tokens
`EVID-S<n>-<hash>` is unique per participant and scenario (HMAC of lab id), so tokens cannot be shared between participants. A token appears only when the flaw is actually demonstrated.

## Answer key
Notation: via Burp, Repeater on `POST /gw/ussd` with JSON `{"input":"…","sessionId":"…"}`. Direct tests use `POST /ussd` (form fields `sessionId`, `input`).

| # | Seeded data | Intended finding | Evidence | Secured profile behaviour |
|---|---|---|---|---|
| 1 | Mallory is the participant SIM; Alice/Bob/Carol are victims | Add header `X-MSISDN: 2348000000001` to the `/gw/ussd` request (the legacy gateway forwards it). Balance of Alice is returned. | S1 (+S2) | Gateway signs identity (HMAC, timestamp, nonce); header ignored; direct `/ussd` returns 401; replayed assertion is rejected and alerts. |
| 2 | Balance and transfers up to NGN 20,000 | Menu 1 and quick transfers need no PIN, only MSISDN recognition. | S2 | PIN required at session start; transfers need PIN re-entry plus OTP (read it at `/lab/outbox`). |
| 3 | Session IDs `S1001…` sequential | Dial as victim via header (or note neighbours' IDs), then continue the victim's session ID from Mallory's request: identity is taken from the session. Also replay: in the transfer confirm step send `1` repeatedly; each executes (state not consumed). Client-chosen session IDs are accepted (fixation). | S3 on the second execution, or on any request that continues another subscriber's session | 192-bit random IDs; bound to the gateway-verified MSISDN; rotated after login; confirm consumed; backend rejects duplicate refs (409). |
| 4 | Sessions never expire | Expiry is client-supplied (`"exp"` field in the JSON body); omit it and the session lives forever; open many sessions for one MSISDN; reuse stale `tr_confirm` state. | S4 when a session is continued after the idle limit, or a client `exp` value is accepted | Idle 90 s and absolute 600 s enforced server-side; one concurrent session per subscriber (new login kills old). Lab values are set by `IDLE` and `ABS`. |
| 5 | Bob PIN `1234`, budget 25 attempts | Transfer above 20,000, enter PINs. Responses give attempt count and PIN length; PIN appears in `/lab/logs`; no lockout. After the correct PIN the confirm screen carries the token. | S5 | scrypt-hashed PIN, 3 failures then progressive lockout (60 s doubling, max 15 min), generic errors, `ALERT` lines without PIN. |
| 6 | Statement search and amount field | Statement reference `' OR 1=1--` returns every user's rows including Carol's note with the token; broken SQL shows the query. Amount `-5000` is accepted (credits the sender); non-numeric amount shows a debug error. | S6 | Regex validation, parameterised query, range checks, generic errors. |
| 7 | `POST /registry/simswap {"msisdn":"2348000000001"}` | After a swap, a transfer as Alice still completes. | S7 | Transfers blocked for `SWAP_WINDOW` (default 900 s) with `ALERT` line. |
| 8 | Backend hop on 127.0.0.1:9000 | `/lab/wire` shows the API key and bodies in cleartext; `/lab/logs` logs the key. `tcpdump -i lo` is not available to participants; the wire log is the tap. | S8 | Plain port refused (403); mTLS on 9443; wire shows only ciphertext length; no key in logs. |
| 9 | `events.csv` per participant, 10 suspicious events of 310 | Repeated SRI-SM from an unlisted GT against Alice; ATI and ProvideSubscriberInfo from non-partner GTs on Carol; UpdateLocation from an unlisted GT for Bob; two Diameter ULRs from an unlisted realm. Submit IDs; need precision and recall at least 0.8. Key per participant: `sudo cat /opt/lab/data/pN/.sig_key.json` (AWS) or `local/labctl_local.sh instructor sigkey N` (local). | S9 | Same task; discuss allow-lists, screening and escalation at the operator. No application-layer toggle. |
| 10 | `/smpp/mo` with `{"source_addr","dest_addr":"32123","message_id","short_message"}` | No authentication; spoofed `source_addr` with `PAY <dest> <amt>` moves money; replay processes again (`times_seen` rises, `billing_rows` rises). | S10 | Needs SMPP-style bind (`/smpp/bind` with `aggr01` / `lab-bind-pass`), validates source and destination, dedups by message ID, rate limits, PAY by SMS disabled. |

## Guardrails built in
Synthetic data only; PIN budget of 25 per account in the vulnerable profile; no outbound connectivity from the range; participants have no Docker access and cannot read `/opt/lab`; signalling is data analysis only.

## Troubleshooting
| Symptom | Fix |
|---|---|
| Range URL not loading | `sudo docker compose -f /opt/lab/docker-compose.yml ps`; `up -d` |
| Burp missing | Installer URL may have changed: download the Linux Community installer, `sudo sh installer.sh -q -dir /opt/burp` |
| Burp browser will not open (sandbox) | Run Burp from terminal; or use Firefox with proxy 127.0.0.1:8080 and allow localhost proxying |
| PIN budget used up | `labctl.sh reset N` |
| Wrong profile | `labctl.sh status` then `mode` |
| Instance stopped | Auto-shutdown fired; start it from the console |
