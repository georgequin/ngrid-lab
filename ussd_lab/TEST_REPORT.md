# Test Report: local instructor and participant environments

## 1. What was and was not run
| Item | Status |
|---|---|
| Both environments built from the real bundles (participant from `student.tar.gz` only) | Done |
| 13 range instances (3 instructor, 10 participant), own ports, secrets, data dirs, backend ports | **Run as processes**, same application code |
| Full pytest suite (35 tests) | **35 passed** in about 43 s (output in section 4) |
| Mutation check: 3 controls deliberately broken, tests must fail | Done, all 3 caught, code restored byte for byte |
| `local/setup.sh`, generated compose files (parsed and checked) | Done |
| `local/labctl_local.sh` status, mode, reset, sigkey, logs against live instances | Done |
| `docker compose up`, image build, container isolation, `mem_limit`, volumes, `restart` | **NOT RUN. Docker is not installed in the sandbox this was built in.** |
| Burp Suite itself | **NOT RUN.** A stand-in proxy on port 8080 was used |
| AWS, Terraform | Untouched, as instructed |

Because Docker was unavailable, the process harness stands in for containers. It proves the application logic and the per-instance separation of data, secrets and ports. It does not prove the Dockerfile builds or that compose behaves. Run the compose stacks once on your machine and then `LAB_MODE=external python -m pytest` (see `local/README.md`); the same tests run unchanged.

## 2. Requirements to tests
| Req | Tests | Result |
|---|---|---|
| 1. All 10 scenarios show flaw and EVID token (vulnerable) | `test_1_vulnerable.py` (10 tests) | Pass |
| 2. All closed in secure profile | `test_2_secure.py` (11 tests): spoofed header and forged or replayed gateway assertion rejected, session rotation, replay consumed, timeouts and concurrency (idle 3 s, absolute 8 s), lockout and generic errors, validation, SIM cooling-off, mTLS hop, SMPP bind, dedup and rate limit, signalling scoring | Pass |
| 3. Isolation | reset and mode toggle do not cross participants; 13 distinct S1 tokens across both environments; 13 distinct signalling keys; instructor token useless on participant env | Pass |
| 4. Bundle and admin | student bundle has no INSTRUCTOR_GUIDE, key files, real tokens, key tooling or answer table; instructor env has the guide and participant env does not; key file not served on 6 URL variants; admin endpoints give 403 for missing, empty, wrong, non-ASCII and near-miss tokens, 400 for a bad mode value | Pass |
| 5. Guardrails | 25 wrong PINs allowed, 26th refused even with the correct PIN, reset restores the budget | Pass |
| 6. Burp readiness | handset UI and `/gw/ussd` through a proxy, tampering via proxy reproduces S1, same tampering fails in secure profile; step-by-step in `local/BURP_SETUP.md` | Pass (stand-in proxy) |

Mutation check (tests must fail when a control is broken): lockout disabled -> `test_s5_throttling...` failed; admin auth always true -> 3 admin and token tests failed; SMPP dedup removed -> `test_s10_smpp...` failed. Original code restored and re-verified identical.

## 3. Bugs and weak points found
### Fixed (explained)
| # | Issue | Fix |
|---|---|---|
| 1 | **Fixed gateway and backend keys.** `GW_KEY` and `BACKEND_KEY` had one shipped default for every instance. Anyone who read `app.py` could forge a signed gateway identity in the secure profile (my own replay test did exactly that). | Keys are now derived per instance from `LAB_SECRET` (`common.py`). Test asserts the old default key is rejected. `GW_KEY` and `BACKEND_KEY` env vars still override. |
| 2 | **`labctl.sh` in the student bundle had a `sigkey` command**, answer-key tooling that should not ship to students. | Removed. Guide now says `sudo cat /opt/lab/data/pN/.sig_key.json` on AWS, `local/labctl_local.sh instructor sigkey N` locally. Test checks the student bundle for it. |
| 3 | **Scenario 4 had no evidence token** and the scenario 3 hijack path produced only S1 and S2 tokens, contrary to the guide. | S4 token shows when a session continues after the idle limit or a client `exp` is accepted. S3 token shows when a session is continued by a different caller identity. Guide updated. |
| 4 | **Scenario 5 token appeared only after money was sent.** The guide says it appears on the confirm screen. | Token now shows as soon as the PIN is accepted ("PIN accepted [EVID-S5-...]"). |
| 5 | **Admin token comparison could raise on non-ASCII input.** `hmac.compare_digest` rejects non-ASCII `str` with `TypeError`, so a crafted header would cause a 500, not a 403. | Both sides compared as bytes. Test covers a non-ASCII header. |
| 6 | **Backend ports and cert dir were hardcoded**, so several instances could not share one host (needed for the harness). | New env vars `BACKEND_PLAIN_PORT`, `BACKEND_TLS_PORT`, `CERT_DIR`, same defaults as before. AWS path unchanged. |
| 7 | `labctl_local.sh status` printed a Python traceback when an instance was down. | Prints `DOWN`. |
| 8 | `/lab/status` did not report timers, so tests could not detect short or long timers. | Added a `timers` field. |

Source files changed: `range/common.py`, `range/app.py`, `range/backend.py`, `range/gen_certs.sh`, `scripts/labctl.sh`, `docs/INSTRUCTOR_GUIDE.md`. Re-run `terraform validate` and your AWS smoke test after pulling these, since the bootstrap uses the same files.

### Open weak points (not changed; your decision)
1. **Docker path untested** (section 1). Most likely things to break first: image build, port publishing, volume permissions.
2. **`/lab/outbox?msisdn=` lets any participant read any subscriber's OTP, even in the secure profile.** It cannot be used to bypass the secure profile, because identity cannot be spoofed there, but it weakens the OTP lesson. Consider limiting it to Mallory when the profile is secure.
3. **`start.sh` does not supervise the backend.** If it dies, the app stays up and returns errors. Add a health check or `wait -n`.
4. **Local participant environment is not hardened.** Source, `.env` and the admin token are readable on disk, and the app source reveals every flaw. On AWS `/opt/lab` is `chmod 700` and participants have no Docker or sudo access.
5. **`SMPP_PASS`, `ADMIN_TOKEN` and `LAB_SECRET` still have weak code defaults** (`lab-bind-pass`, `admin`, `change-me`). Compose and the AWS bootstrap always set `ADMIN_TOKEN` and `LAB_SECRET`. `SMPP_PASS` stays fixed because the guide discloses it at validation time. Refuse to start when `ADMIN_TOKEN` is unset if you want a hard guarantee.
6. **Scenario 9 pass mark** accepts 8 of 10 with no false positives. Tighten the 0.8 threshold in `app.py` if you want stricter marking.
7. **Burp Suite Community not exercised**, only a stand-in proxy.

## 4. Raw test output
```
test_1_vulnerable.py::test_s1_msisdn_header_trust PASSED           [  2%]
test_1_vulnerable.py::test_s2_msisdn_only_access PASSED            [  5%]
test_1_vulnerable.py::test_s3_replay_hijack_predictable_ids PASSED [  8%]
test_1_vulnerable.py::test_s4_timeout_and_concurrency PASSED       [ 11%]
test_1_vulnerable.py::test_s5_weak_pin_no_throttling PASSED        [ 14%]
test_1_vulnerable.py::test_s6_validation_and_injection PASSED      [ 17%]
test_1_vulnerable.py::test_s7_sim_swap_ignored PASSED              [ 20%]
test_1_vulnerable.py::test_s8_plaintext_hop_and_logged_credentials PASSED [ 22%]
test_1_vulnerable.py::test_s9_signalling_dataset PASSED            [ 25%]
test_1_vulnerable.py::test_s10_smpp_spoof_replay_billing PASSED    [ 28%]
test_2_secure.py::test_s1_identity_not_from_headers PASSED         [ 31%]
test_2_secure.py::test_s2_pin_required PASSED                      [ 34%]
test_2_secure.py::test_s3_session_rotation_replay_entropy PASSED   [ 37%]
test_2_secure.py::test_s4_timeouts_and_concurrency PASSED          [ 40%]
test_2_secure.py::test_s5_throttling_lockout_generic_errors_no_pin_logging PASSED [ 42%]
test_2_secure.py::test_s6_validation PASSED                        [ 45%]
test_2_secure.py::test_s7_sim_swap_cooling_off PASSED              [ 48%]
test_2_secure.py::test_s8_hop_not_visible_and_no_secret_logging PASSED [ 51%]
test_2_secure.py::test_s8_plain_port_refused_and_mtls_enforced PASSED [ 54%]
test_2_secure.py::test_s9_signalling_scoring PASSED                [ 57%]
test_2_secure.py::test_s10_smpp_bind_dedup_validation_rate_limit PASSED [ 60%]
test_3_isolation_bundle_guardrails.py::test_reset_and_mode_toggle_do_not_cross_participants PASSED [ 62%]
test_3_isolation_bundle_guardrails.py::test_evidence_tokens_unique_per_participant_and_environment PASSED [ 65%]
test_3_isolation_bundle_guardrails.py::test_signalling_keys_and_events_differ_per_participant PASSED [ 68%]
test_3_isolation_bundle_guardrails.py::test_instances_have_separate_secrets_and_tokens PASSED [ 71%]
test_3_isolation_bundle_guardrails.py::test_student_bundle_has_no_instructor_material PASSED [ 74%]
test_3_isolation_bundle_guardrails.py::test_instructor_bundle_has_guide_and_answer_key PASSED [ 77%]
test_3_isolation_bundle_guardrails.py::test_instructor_env_has_docs_participant_env_does_not PASSED [ 80%]
test_3_isolation_bundle_guardrails.py::test_signalling_key_not_served PASSED [ 82%]
test_3_isolation_bundle_guardrails.py::test_admin_endpoints_reject_missing_or_wrong_token[/admin/mode-body0] PASSED [ 85%]
test_3_isolation_bundle_guardrails.py::test_admin_endpoints_reject_missing_or_wrong_token[/admin/reset-None] PASSED [ 88%]
test_3_isolation_bundle_guardrails.py::test_pin_budget_is_25_and_reset_restores_it PASSED [ 91%]
test_4_burp_proxy.py::test_handset_ui_and_gateway_work_through_proxy PASSED [ 94%]
test_4_burp_proxy.py::test_header_tampering_in_proxy_reproduces_scenario_1 PASSED [ 97%]
test_4_burp_proxy.py::test_same_tampering_fails_in_secure_profile PASSED [100%]
============================= 35 passed in 43.55s ==============================
```

## 5. Exact commands
See `local/README.md` for the full list. Short form (replace `participant` with `instructor` for the other environment):
```bash
./local/setup.sh                                   # or TEST_TIMERS=1 ./local/setup.sh for tests
./local/labctl_local.sh participant up             # start
./local/labctl_local.sh participant down           # stop
./local/labctl_local.sh participant reset [N]      # re-seed all or one
./local/labctl_local.sh participant mode secure|vulnerable [N]
python -m pytest                                   # test suite, no Docker needed
```
