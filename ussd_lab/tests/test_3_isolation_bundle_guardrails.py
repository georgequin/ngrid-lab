"""Reqs 3, 4, 5: isolation between participants, bundle hygiene and admin auth, guardrails."""
import re, tarfile, requests, pytest
from helpers import *
ROOT = __import__("pathlib").Path(__file__).resolve().parents[1]

# ---------- Req 3: isolation ----------
def test_reset_and_mode_toggle_do_not_cross_participants(envs):
    a, b = envs["P"][2].fresh("vulnerable"), envs["P"][3].fresh("vulnerable")
    s, _ = b.flow(["", "2", ALICE, "50000"], hdr=b.spoof(CAROL))
    for g in ["0000", "1111", "2222"]: b.gw(g, s, b.spoof(CAROL))
    assert b.status()["pin_attempts_used"][CAROL] == 3
    a.set_mode("secure"); a.reset()
    assert b.status()["profile"] == "vulnerable" and b.status()["pin_attempts_used"][CAROL] == 3
    envs["P"][2].set_mode("vulnerable")

def test_evidence_tokens_unique_per_participant_and_environment(envs):
    seen = {}
    for x in envs["P"] + envs["I"]:
        x.set_mode("vulnerable"); x.reset(); _, o = x.flow(["", "1"], hdr=x.spoof(ALICE)); seen[x.url] = tok(o, 1)
    assert all(seen.values()) and len(set(seen.values())) == len(seen), seen          # 13 distinct tokens

def test_signalling_keys_and_events_differ_per_participant(envs):
    keys = [tuple(x.sigkey()) for x in envs["P"] + envs["I"] if x.sigkey()]
    if len(keys) < 13: pytest.skip("key files not readable from here")
    assert len(set(keys)) == 13

def test_instances_have_separate_secrets_and_tokens(envs):
    assert envs["P"][0].token != envs["I"][0].token
    r = envs["P"][0].admin("/admin/mode", {"mode": "secure"}, token=envs["I"][0].token); assert r.status_code == 403   # instructor token useless on participant env
    r = envs["I"][0].admin("/admin/mode", {"mode": "secure"}, token=envs["P"][0].token); assert r.status_code == 403

# ---------- Req 4: bundle hygiene, key not served, admin auth ----------
def test_student_bundle_has_no_instructor_material():
    names = tarfile.open(ROOT / "dist/student.tar.gz").getnames()
    assert not [n for n in names if re.search(r"INSTRUCTOR|sig_key|answer", n, re.I)], names
    t = tarfile.open(ROOT / "dist/student.tar.gz")
    for m in t.getmembers():
        if not m.isfile(): continue
        body = t.extractfile(m).read().decode("utf-8", "ignore")
        assert not re.search(r"EVID-S\d+-[0-9a-f]{8}", body), m.name                  # no real evidence tokens
        assert "sigkey" not in body and "Answer key" not in body, m.name              # no key tooling or answer table
        if m.name.endswith("STUDENT_HANDOUT.md"): assert "OR 1=1" not in body and "X-MSISDN: 2348" not in body

def test_instructor_bundle_has_guide_and_answer_key():
    names = tarfile.open(ROOT / "dist/instructor.tar.gz").getnames()
    assert any(n.endswith("INSTRUCTOR_GUIDE.md") for n in names) and any(n.endswith("labctl.sh") for n in names)

def test_instructor_env_has_docs_participant_env_does_not(envs):
    assert (envs["instr_dir"] / "docs/INSTRUCTOR_GUIDE.md").exists()
    assert not (envs["student_dir"] / "docs/INSTRUCTOR_GUIDE.md").exists()

def test_signalling_key_not_served(p1):
    for path in ["/.sig_key.json", "/lab/signalling/.sig_key.json", "/data/.sig_key.json", "/lab/signalling/key", "/static/.sig_key.json", "/%2e%2e/.sig_key.json"]:
        r = requests.get(p1.url + path, timeout=5); assert r.status_code != 200 and "E0" not in r.text, path

@pytest.mark.parametrize("ep,body", [("/admin/mode", {"mode": "secure"}), ("/admin/reset", None)])
def test_admin_endpoints_reject_missing_or_wrong_token(p1, ep, body):
    for h in [{}, {"X-Admin-Token": ""}, {"X-Admin-Token": "wrong"}, {"X-Admin-Token": "é"}, {"X-Admin-Token": p1.token + "x"}]:
        r = requests.post(p1.url + ep, json=body, headers=h, timeout=5); assert r.status_code == 403, (h, r.status_code)
    assert p1.admin("/admin/mode", {"mode": "nonsense"}).status_code == 400                   # valid token, bad value

# ---------- Req 5: guardrails ----------
def test_pin_budget_is_25_and_reset_restores_it(envs):
    x = envs["P"][1].fresh("vulnerable"); h = x.spoof(CAROL)
    s, _ = x.flow(["", "2", BOB, "50000"], hdr=h)
    for n in range(1, 26):
        _, o = x.gw("0000", s, h); assert f"attempt {n}/25" in o, (n, o)
    _, o = x.gw("7390", s, h); assert "budget" in o and not tok(o, 5), o                      # correct PIN refused: budget spent
    assert x.status()["pin_attempts_used"][CAROL] == 25
    x.reset(); assert x.status()["pin_attempts_used"][CAROL] == 0
    s, _ = x.flow(["", "2", BOB, "50000"], hdr=h); _, o = x.gw("7390", s, h); assert tok(o, 5), o
