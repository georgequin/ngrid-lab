"""Req 1: every scenario shows its flaw and its EVID token in the vulnerable profile."""
import time, requests
from helpers import *

def test_s1_msisdn_header_trust(vul):
    _, o = vul.flow(["", "1"], hdr=vul.spoof(ALICE))
    assert "150000" in o and tok(o, 1) and tok(o, 2), o

def test_s2_msisdn_only_access(vul):
    _, o = vul.flow(["", "1"]); assert "Enter PIN" not in o and tok(o, 2), o
    _, o = vul.flow(["", "2", ALICE, "100", "1"]); assert "Sent NGN 100" in o and tok(o, 2), o

def test_s3_replay_hijack_predictable_ids(vul):
    _, o = vul.flow(["", "2", ALICE, "100", "1", "1"]); assert "(#2)" in o and tok(o, 3), o      # confirm replay
    victim, _ = vul.gw("", hdr=vul.spoof(ALICE))                                                 # victim session
    _, o = vul.gw("1", victim); assert "150200" in o and tok(o, 3), o                            # continued by Mallory (150000 + 2 replayed transfers)
    a, _ = vul.gw(""); b, _ = vul.gw(""); assert int(b[1:]) - int(a[1:]) == 1                    # sequential IDs
    s, _ = vul.gw("", "ATTACKER-CHOSEN"); assert s == "ATTACKER-CHOSEN"                          # fixation

def test_s4_timeout_and_concurrency(vul, short):
    a, _ = vul.gw(""); b, _ = vul.gw("")                                                         # concurrent sessions
    assert vul.gw("9", a)[1].startswith("CON") and vul.gw("9", b)[1].startswith("CON")
    s, _ = vul.gw(""); _, o = vul.gw("9", s, exp=time.time() - 1); assert "expired" in o          # client controls expiry
    s, _ = vul.gw(""); _, o = vul.gw("9", s, exp=time.time() + 3600); assert tok(o, 4), o
    s, _ = vul.gw(""); time.sleep(vul.status()["timers"]["idle"] + 1)                             # not enforced server-side
    _, o = vul.gw("9", s); assert "expired" not in o and tok(o, 4), o

def test_s5_weak_pin_no_throttling(vul):
    s, _ = vul.flow(["", "2", CAROL, "50000"], hdr=vul.spoof(BOB))
    for n, g in enumerate(["0000", "1111", "2222"], 1):
        _, o = vul.gw(g, s, vul.spoof(BOB)); assert f"attempt {n}/25" in o and "PIN length is 4" in o
    _, o = vul.gw("1234", s, vul.spoof(BOB)); assert "Send NGN 50000" in o and tok(o, 5), o
    assert "pin=1234" in vul.get("/lab/logs").text                                               # PIN logged in clear

def test_s6_validation_and_injection(vul):
    h = vul.spoof(ALICE)
    _, o = vul.flow(["", "3", "' OR 1=1--"], hdr=h); assert tok(o, 6), o                          # Carol's note leaks
    _, o = vul.flow(["", "3", "'"], hdr=h); assert "SQL error" in o and "SELECT" in o             # verbose SQL error
    _, o = vul.flow(["", "2", BOB, "-5000", "1"], hdr=h); assert tok(o, 6), o                     # negative amount
    _, o = vul.flow(["", "2", BOB, "abc"], hdr=h); assert "ERR" in o and "debug" in o

def test_s7_sim_swap_ignored(vul):
    assert vul.post("/registry/simswap", json={"msisdn": ALICE}).status_code == 200
    _, o = vul.flow(["", "2", BOB, "100", "1"], hdr=vul.spoof(ALICE)); assert "Sent NGN 100" in o and tok(o, 7), o

def test_s8_plaintext_hop_and_logged_credentials(vul):
    vul.flow(["", "1"], hdr=vul.spoof(ALICE))
    w = vul.get("/lab/wire").text; assert "X-Api-Key" in w and tok(w, 8), w
    assert "api_key=" in vul.get("/lab/logs").text

def test_s9_signalling_dataset(vul):
    key = vul.sigkey()
    if key is None: import pytest; pytest.skip("signalling key not readable from here")
    ev = vul.get("/lab/signalling/events.csv").text.splitlines()[1:]; assert len(ev) >= 300 and len(key) == 10
    assert tok(vul.post("/lab/signalling/submit", json={"event_ids": key}).text, 9)
    assert not tok(vul.post("/lab/signalling/submit", json={"event_ids": []}).text, 9)

def test_s10_smpp_spoof_replay_billing(vul):
    m = {"source_addr": ALICE, "dest_addr": "32123", "message_id": "m1", "short_message": f"PAY {MAL} 1000"}
    j = vul.post("/smpp/mo", json=m).json(); assert j["result"] == "PAY_200" and tok(j["evidence"], 10)
    assert vul.post("/smpp/mo", json=m).json()["times_seen"] == 2                                 # replay accepted
    vul.post("/smpp/mo", json={**m, "source_addr": MAL, "message_id": "m2", "short_message": "BAL"})
    assert "Balance NGN 7000" in vul.get(f"/lab/outbox?msisdn={MAL}").json()[0]["text"]           # paid twice
    assert vul.status()["billing_rows"] == 3
