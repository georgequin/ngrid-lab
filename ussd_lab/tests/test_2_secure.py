"""Req 2: every scenario is closed in the secure profile (short timers: idle 3 s, abs 8 s, SIM window 5 s)."""
import time, requests, pytest
from helpers import *

def test_s1_identity_not_from_headers(sec):
    forged = signed_headers(b"gw-shared-key-lab", ALICE)                                              # the old shipped default key
    assert sec.post("/ussd", data={"input": "", "sessionId": ""}, headers=forged).status_code == 401
    assert sec.post("/ussd", data={"input": "", "sessionId": ""}, headers={"X-MSISDN": ALICE}).status_code == 401
    s, o = sec.gw("", hdr=sec.spoof(ALICE)); assert "Enter PIN" in o
    s, _ = sec.gw("2580", s); _, o = sec.gw("1", s); assert "NGN 5000" in o and "150000" not in o   # still Mallory
    h = signed_headers(gw_key(sec.secret)); assert sec.post("/ussd", data={"input": "", "sessionId": ""}, headers=h).status_code == 200
    r = sec.post("/ussd", data={"input": "", "sessionId": ""}, headers=h); assert r.status_code == 401   # replayed assertion
    stale = signed_headers(gw_key(sec.secret)); stale["X-GW-TS"] = str(int(stale["X-GW-TS"]) - 120)
    assert sec.post("/ussd", data={"input": "", "sessionId": ""}, headers=stale).status_code == 401      # bad sig/ts

def test_s2_pin_required(sec):
    s, o = sec.gw(""); assert "Enter PIN" in o and "Balance" not in o
    _, o = sec.gw("1", s); assert o.startswith("END") and "NGN" not in o                             # menu not reachable
    s, _ = sec.gw(""); _, o = sec.gw("2580", s); assert "1 Balance" in o

def test_s3_session_rotation_replay_entropy(sec):
    s, _ = sec.gw(""); s2, _ = sec.gw("2580", s); assert s2 != s and len(s2) >= 30
    assert "invalid" in sec.gw("1", s)[1].lower()                                                    # old id dead after login
    sid, o = secure_transfer_to_confirm(sec); assert "Send NGN 100" in o
    assert "Transfer done" in sec.gw("1", sid)[1]
    _, o = sec.gw("1", sid); assert "NGN 4900" in o, o            # replayed "1" is just the Balance option; no 2nd transfer

def test_s4_timeouts_and_concurrency(sec, short):
    t = sec.status()["timers"]
    s = sec.login(); assert sec.gw("9", s)[1].startswith("CON"); time.sleep(t["idle"] + 1)
    assert "expired" in sec.gw("9", s)[1]                                                            # idle timeout
    s = sec.login(); time.sleep(t["idle"] + 1)
    assert "expired" in sec.gw("9", s, exp=time.time() + 99999)[1]                                   # client exp ignored
    s = sec.login(); t0 = time.time(); out = None
    while time.time() - t0 < t["abs"] + 4:                                                           # activity keeps idle alive
        time.sleep(1); o = sec.gw("9", s)[1]
        if o.startswith("END"): out = (time.time() - t0, o); break
    assert out and out[0] >= t["abs"] - 1 and "expired" in out[1], out                               # absolute timeout
    a = sec.login(); b = sec.login(); assert "invalid" in sec.gw("1", a)[1].lower() and "NGN" in sec.gw("1", b)[1]

def test_s5_throttling_lockout_generic_errors_no_pin_logging(sec):
    msgs = []
    for _ in range(3):
        s, _o = sec.gw(""); msgs.append(sec.gw("0000", s)[1])
    assert msgs[0] == msgs[1] == "END Authentication failed." and "attempt" not in msgs[0] and "length" not in msgs[0]
    s, _ = sec.gw(""); assert "Try later" in sec.gw("2580", s)[1]                                    # right PIN refused while locked
    logs = sec.get("/lab/logs").text; assert logs.count("ALERT failed PIN") >= 3 and "pin=" not in logs
    assert "ALERT attempt during lockout" in logs

def test_s6_validation(sec):
    def stmt(v): s = sec.login(); sec.gw("3", s); return sec.gw(v, s)[1]
    for bad in ["' OR 1=1--", "'", "A" * 5000, "💥", "a;b"]: assert "Invalid reference" in stmt(bad), bad
    def amt(v): s = sec.login(); sec.gw("2", s); sec.gw(ALICE, s); return sec.gw(v, s)[1]
    for bad in ["-5000", "abc", "0", "99999999", "1e9", " "]: assert "Invalid amount" in amt(bad), bad
    s = sec.login(); sec.gw("2", s); assert "Invalid recipient" in sec.gw("not-a-number", s)[1]

def test_s7_sim_swap_cooling_off(sec, short):
    def to_pin(): s = sec.login(); sec.gw("2", s); sec.gw(ALICE, s); return sec.gw("100", s)[1]
    assert "PIN" in to_pin()
    sec.post("/registry/simswap", json={"msisdn": MAL}); o = to_pin(); assert "restricted" in o, o
    assert "ALERT transfer blocked" in sec.get("/lab/logs").text
    time.sleep(sec.status()["timers"]["swap_window"] + 1); assert "PIN" in to_pin()

def test_s8_hop_not_visible_and_no_secret_logging(sec):
    s = sec.login(); sec.gw("1", s)
    w = sec.get("/lab/wire").text; assert "TLS1.3" in w and "X-Api-Key" not in w and not tok(w, 8)
    l = sec.get("/lab/logs").text; assert "(mTLS)" in l and "api_key=" not in l

def test_s8_plain_port_refused_and_mtls_enforced(sec, envs, needs_process):
    h = {"X-Api-Key": bk_key(sec.secret)}; ca = str(envs["certs"] / "ca.crt")
    assert requests.get(f"http://127.0.0.1:{sec.bk_plain}/balance/{MAL}", headers=h).status_code == 403
    with pytest.raises(requests.exceptions.RequestException):                                        # no client cert
        requests.get(f"https://localhost:{sec.bk_tls}/balance/{MAL}", headers=h, verify=ca)
    r = requests.get(f"https://localhost:{sec.bk_tls}/balance/{MAL}", headers=h, verify=ca, cert=(str(envs["certs"] / "client.crt"), str(envs["certs"] / "client.key")))
    assert r.status_code == 200

def test_s9_signalling_scoring(sec):
    key = sec.sigkey()
    if key is None: pytest.skip("signalling key not readable from here")
    ev = [l.split(",")[0] for l in sec.get("/lab/signalling/events.csv").text.splitlines()[1:]]
    sub = lambda ids: sec.post("/lab/signalling/submit", json={"event_ids": ids}).json()
    assert tok(str(sub(key)), 9) and tok(str(sub(key[:8])), 9)
    assert not tok(str(sub(key[:5])), 9) and not tok(str(sub(ev)), 9) and not tok(str(sub(key + [e for e in ev if e not in key][:10])), 9)

def test_s10_smpp_bind_dedup_validation_rate_limit(sec):
    m = {"source_addr": ALICE, "dest_addr": "32123", "message_id": "z1", "short_message": "BAL"}
    assert sec.post("/smpp/mo", json=m).status_code == 401                                           # unbound
    t = sec.post("/smpp/bind", json={"system_id": "aggr01", "password": "lab-bind-pass"}).json()["bind_token"]; a = {"Authorization": "Bearer " + t}
    assert sec.post("/smpp/mo", json=m, headers=a).json()["result"] == "BAL_SENT"
    assert sec.post("/smpp/mo", json=m, headers=a).json()["status"] == "DUPLICATE_IGNORED"
    assert sec.post("/smpp/mo", json={**m, "message_id": "z2", "source_addr": "1234"}, headers=a).status_code == 400
    assert sec.post("/smpp/mo", json={**m, "message_id": "z3", "dest_addr": "999"}, headers=a).status_code == 400
    assert sec.post("/smpp/mo", json={**m, "message_id": "z4", "short_message": f"PAY {MAL} 1000"}, headers=a).json()["result"] == "PAY_DISABLED"
    codes = [sec.post("/smpp/bind", json={"system_id": "aggr01", "password": "wrong"}).status_code for _ in range(6)]
    assert 429 in codes and "ALERT failed SMPP bind" in sec.get("/lab/logs").text
