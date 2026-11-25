# USSD & Telecom Channel Security: Student Lab Handout

All data in this range is **synthetic**. There is no real bank, no real subscriber and no live telecom network (no SS7/Diameter connectivity at all). Test only your own range at `http://127.0.0.1:800N` (N = your user number, p1 to p10).

## Setup (5 minutes)
1. Log in to your team desktop as `pN` (password from your instructor).
2. Open **Burp Suite** (Community). Use *Temporary project*, then *Proxy > Open browser*.
3. In Burp's browser open your range URL (see `MY_RANGE.txt` on the Desktop). You see a USSD handset simulator. Press **Dial**.
4. Confirm traffic shows up in Burp *Proxy > HTTP history*.

Your SIM is **Mallory (+2348000000009)**, PIN 2580. Other synthetic subscribers: Alice (…0001), Bob (…0002), Carol (…0003). Helper endpoints on your range: `/lab/status`, `/lab/logs`, `/lab/wire`, `/lab/outbox?msisdn=`, `/lab/signalling/events.csv`, `/lab/signalling/peers.json`, `/registry/simswap` (POST), `/smpp/mo` (POST JSON).

## Rules
* Test **only** your own range and **only** the seeded accounts above.
* Scenario 5 has a fixed attempt budget (25 per account). It shows missing throttling; it is not a guessing tool. Intruder in Burp Community is rate-limited, so use Repeater.
* Every confirmed finding yields an **evidence token** (`EVID-S<n>-xxxxxxxx`). Record it, the request that produced it, and your remediation recommendation.

## Evidence template (one per scenario)
| Field | Your entry |
|---|---|
| Scenario / ID | |
| Objective tested | |
| Request(s) sent (Burp Repeater tab / screenshot) | |
| Observed behaviour | |
| Evidence token | |
| Business impact (Low / Med / High and why) | |
| Recommended control | |
| Retest result in secured profile (after instructor switches it) | |

## Scenario objectives
1. **MSISDN trust:** Can you make the application treat you as a different subscriber by changing something in the request? Which parts of the request does the application believe?
2. **Single-factor access:** Which menu paths reveal balances or move money without proof you are the subscriber?
3. **Session hijack / replay:** Examine session identifiers and state. Can another synthetic subscriber's session be continued or a completed action be repeated?
4. **Timeout / concurrency:** Do sessions expire? Who decides? What happens with two sessions for one subscriber and stale menu state?
5. **Weak PIN / throttling:** Using Bob's account and the attempt budget, how does the system behave on repeated failures? What do responses and `/lab/logs` reveal?
6. **Input validation:** Try boundary values, unexpected menu choices, long input, Unicode, delimiters and the predefined test strings from your instructor. Also read the error messages.
7. **SIM-swap:** POST a SIM-change event for a subscriber, then test whether a sensitive transaction still goes through unchallenged.
8. **Transport / trust boundary:** Compare `/lab/wire` in the vulnerable and secured profiles. What is visible at each boundary? What else is exposed in `/lab/logs`?
9. **Signalling simulation:** Review `events.csv` against `peers.json`. List suspicious event IDs and justify each. Submit them to `POST /lab/signalling/submit` as `{"event_ids":[...]}`.
10. **MO-SMS / SMPP:** Send normal and malformed synthetic events to `/smpp/mo`. Assess source binding, duplicate handling, replay and billing (`/lab/status`).

## Validation phase
After remediation is explained, your instructor switches your range to the **secured profile**. Repeat each test and record what changed and why.
