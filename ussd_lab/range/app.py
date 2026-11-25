"""USSD banking range. SYNTHETIC DATA ONLY. Deliberately vulnerable in the 'vulnerable' profile.
Profile is read from /data/mode and toggled by the instructor via /admin/mode."""
import os, re, time, json, hmac, hashlib, secrets, sqlite3, csv
import requests
from flask import Flask, request, jsonify, Response
from common import *

app = Flask(__name__)
APP_DB = f"{DATA}/app.db"
PORT = int(os.environ.get("PORT", "8080"))
ADMIN = os.environ.get("ADMIN_TOKEN", "admin")
SMPP_PASS = os.environ.get("SMPP_PASS", "lab-bind-pass")
MALLORY = "2348000000009"          # the participant's own (attacker) SIM
PIN_BUDGET = 25                    # brute-force guardrail: hard cap per account in the vulnerable profile
IDLE, ABS = int(os.environ.get("IDLE", 90)), int(os.environ.get("ABS", 600))
SWAP_WINDOW = int(os.environ.get("SWAP_WINDOW", 900))   # seconds a SIM change is "recent"
QUICK_LIMIT = 20000
_epoch = [None]

# ---------- storage ----------
def q(sql, args=(), one=False, commit=False):
    c = sqlite3.connect(APP_DB); c.row_factory = sqlite3.Row
    try:
        cur = c.execute(sql, args)
        if commit: c.commit()
        return (cur.fetchone() if one else cur.fetchall())
    finally:
        c.close()

def hpin(m, p): return hashlib.scrypt(p.encode(), salt=m.encode(), n=2**11, r=8, p=1).hex()

def init_db():
    if os.path.exists(APP_DB): os.remove(APP_DB)
    c = sqlite3.connect(APP_DB)
    c.executescript("""
    CREATE TABLE subscribers(msisdn TEXT PRIMARY KEY, name TEXT, pin_plain TEXT, pin_hash TEXT, sim_changed REAL DEFAULT 0, fails INTEGER DEFAULT 0, locked_until REAL DEFAULT 0, pin_tries INTEGER DEFAULT 0);
    CREATE TABLE sessions(id TEXT PRIMARY KEY, msisdn TEXT, state TEXT, created REAL, last REAL, exp REAL);
    CREATE TABLE nonces(n TEXT PRIMARY KEY);
    CREATE TABLE outbox(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, msisdn TEXT, text TEXT);
    CREATE TABLE otps(msisdn TEXT PRIMARY KEY, code TEXT, exp REAL, tries INTEGER);
    CREATE TABLE seen(msg_id TEXT, n INTEGER);
    CREATE TABLE billing(id INTEGER PRIMARY KEY AUTOINCREMENT, src TEXT, msg_id TEXT);
    CREATE TABLE binds(token TEXT PRIMARY KEY, exp REAL);
    CREATE TABLE rate(k TEXT, ts REAL);
    CREATE TABLE ctr(v INTEGER);
    INSERT INTO ctr VALUES(0);
    """)
    for m, n, p in [("2348000000001", "Alice Test", "4821"), ("2348000000002", "Bob Test", "1234"),
                    ("2348000000003", "Carol Test", "7390"), (MALLORY, "Mallory (your SIM)", "2580")]:
        c.execute("INSERT INTO subscribers(msisdn,name,pin_plain,pin_hash) VALUES(?,?,?,?)", (m, n, p, hpin(m, p)))
    c.commit(); c.close()

def sync_epoch():
    if _epoch[0] != epoch():
        _epoch[0] = epoch(); init_db(); log("lab (re)seeded")

@app.before_request
def _b(): sync_epoch()

def plain(t, code=200, sid=None):
    r = Response(t, code, mimetype="text/plain")
    if sid: r.headers["X-Session-Id"] = sid
    return r

def admin_only():
    return hmac.compare_digest(request.headers.get("X-Admin-Token", "").encode("utf-8", "ignore"), ADMIN.encode())

# ---------- backend hop (scenario 8) ----------
def bk(method, path, **kw):
    sec = mode() == "secure"
    if sec:
        url = f"https://localhost:{BK_TLS}{path}"
        kw.update(cert=(f"{CERT_DIR}/client.crt", f"{CERT_DIR}/client.key"), verify=f"{CERT_DIR}/ca.crt")
        log(f"-> backend {method} {path} (mTLS)")
    else:
        url = f"http://127.0.0.1:{BK_PLAIN}{path}"
        log(f"-> backend {method} {path} api_key={BK_KEY} body={json.dumps(kw.get('json') or kw.get('params'))}")  # credential logging (flaw)
    return requests.request(method, url, headers={"X-Api-Key": BK_KEY}, timeout=5, **kw)

# ---------- identity (scenario 1) ----------
def verify_gw():
    h = request.headers
    m, ts, n, sig = h.get("X-GW-MSISDN"), h.get("X-GW-TS"), h.get("X-GW-NONCE"), h.get("X-GW-SIG", "")
    try:
        if not (m and ts and n and sig): return None
        exp = hmac.new(GW_KEY.encode(), f"{m}|{ts}|{n}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(exp, sig) or abs(time.time() - int(ts)) > 30: return None
    except Exception:
        return None
    if q("SELECT 1 FROM nonces WHERE n=?", (n,), one=True):
        log(f"ALERT replayed gateway assertion nonce={n}"); return None
    q("INSERT INTO nonces VALUES(?)", (n,), commit=True)
    return m

@app.post("/gw/ussd")
def gateway():
    """Simulated operator USSD gateway. The handset (this lab's Mallory SIM) talks to it."""
    b = request.get_json(force=True, silent=True) or {}
    data = {"sessionId": b.get("sessionId", ""), "input": str(b.get("input", ""))}
    if b.get("exp"): data["exp"] = b["exp"]
    if mode() == "secure":   # verified gateway identity: signed assertion, timestamp + nonce
        ts, nonce = str(int(time.time())), secrets.token_hex(8)
        sig = hmac.new(GW_KEY.encode(), f"{MALLORY}|{ts}|{nonce}".encode(), hashlib.sha256).hexdigest()
        hdr = {"X-GW-MSISDN": MALLORY, "X-GW-TS": ts, "X-GW-NONCE": nonce, "X-GW-SIG": sig}
    else:                    # legacy gateway forwards a client-supplied identity header
        hdr = {"X-MSISDN": request.headers.get("X-MSISDN") or MALLORY}
    r = requests.post(f"http://127.0.0.1:{PORT}/ussd", data=data, headers=hdr, timeout=10)
    return jsonify(sessionId=r.headers.get("X-Session-Id", data["sessionId"]), screen=r.text, end=r.text.startswith("END"))

# ---------- sessions (scenarios 3, 4) ----------
def seq():
    q("UPDATE ctr SET v=v+1", commit=True); return q("SELECT v FROM ctr", one=True)["v"]

def create_session(sid, msisdn, st):
    now = time.time()
    q("INSERT OR REPLACE INTO sessions VALUES(?,?,?,?,?,?)", (sid, msisdn, json.dumps(st), now, now, None), commit=True)

def swapped(m):
    r = q("SELECT sim_changed FROM subscribers WHERE msisdn=?", (m,), one=True)
    return bool(r and r["sim_changed"] and time.time() - r["sim_changed"] < SWAP_WINDOW)

def check_pin(m, pin, sec):
    s = q("SELECT * FROM subscribers WHERE msisdn=?", (m,), one=True); now = time.time()
    if sec:   # secure: hashed, throttled, progressive lockout, generic errors, no PIN logging
        if s["locked_until"] > now:
            log(f"ALERT attempt during lockout msisdn={m}"); return False, "Authentication failed. Try later.", True
        if hmac.compare_digest(s["pin_hash"], hpin(m, pin)):
            q("UPDATE subscribers SET fails=0 WHERE msisdn=?", (m,), commit=True); return True, "", False
        f = s["fails"] + 1; lock = now + min(60 * 2 ** (f - 3), 900) if f >= 3 else 0
        q("UPDATE subscribers SET fails=?, locked_until=? WHERE msisdn=?", (f, lock, m), commit=True)
        log(f"ALERT failed PIN msisdn={m} count={f} src={request.remote_addr}")
        return False, "Authentication failed.", f >= 3
    if s["pin_tries"] >= PIN_BUDGET:   # lab guardrail, not a security control
        return False, "Lab attempt budget used up for this account. Ask the instructor to reset.", True
    tries = s["pin_tries"] + 1
    q("UPDATE subscribers SET pin_tries=? WHERE msisdn=?", (tries, m), commit=True)
    log(f"PIN attempt #{tries} msisdn={m} pin={pin}")   # PIN logged in clear (flaw)
    if pin == s["pin_plain"]: return True, ev(5), False
    return False, f"Wrong PIN (attempt {tries}/{PIN_BUDGET}). PIN length is {len(s['pin_plain'])}.", False

MENU = "CON My Bank\n1 Balance\n2 Transfer\n3 Statement\n0 Exit"
def screen(st):
    c = st["ctx"]
    return {"root": MENU, "pin": "CON Enter PIN", "tr_dest": "CON Recipient number (2348...)", "tr_amt": "CON Amount (NGN)",
            "tr_pin": "CON Confirm with your PIN", "tr_otp": "CON Enter the OTP sent by SMS",
            "tr_confirm": f"CON Send NGN {c.get('amt')} to {c.get('dest')}?\n1 Yes\n2 No",
            "stmt": "CON Transaction ref (0 = last entries)"}[st["step"]]

def logic(msisdn, st, inp, sec):
    step, c = st["step"], st["ctx"]
    if step == "pin":
        ok, msg, end = check_pin(msisdn, inp, True)
        if ok: st.update(authed=True, step="root", _rotate=True); return MENU
        return "END " + msg
    if step == "root":
        if inp == "1":
            if sec and not st["authed"]: return "END Not authenticated"
            bal = bk("GET", f"/balance/{msisdn}").json().get("balance")
            t = f"END Balance: NGN {bal}"
            if not sec: t += f" [{ev(2)}]" + (f" [{ev(1)}]" if msisdn != MALLORY else "")
            return t
        if inp == "2": st["step"] = "tr_dest"; st["ctx"] = {}; return screen(st)
        if inp == "3": st["step"] = "stmt"; return screen(st)
        if inp == "0": return "END Goodbye"
        return "CON Invalid choice\n" + MENU[4:]
    if step == "tr_dest":
        if sec and not (re.fullmatch(r"234\d{10}", inp) and q("SELECT 1 FROM subscribers WHERE msisdn=?", (inp,), one=True)):
            return "CON Invalid recipient\n" + screen(st)[4:]
        c["dest"] = inp; st["step"] = "tr_amt"; return screen(st)
    if step == "tr_amt":
        if sec:
            if not re.fullmatch(r"[1-9]\d{0,6}", inp): return "CON Invalid amount\n" + screen(st)[4:]
            amt = int(inp)
            if swapped(msisdn):
                log(f"ALERT transfer blocked, recent SIM change msisdn={msisdn}")
                return "END Transfers are restricted after a recent SIM change. Try later or visit a branch."
        else:
            try: amt = int(inp)
            except ValueError as e: return f"END ERR {e!r} (ussd.logic line 118, debug build)"   # verbose errors (flaw)
        c.update(amt=amt, ref=secrets.token_hex(6))
        st["step"] = "tr_pin" if (sec or amt > QUICK_LIMIT) else "tr_confirm"
        return screen(st)
    if step == "tr_pin":
        ok, msg, end = check_pin(msisdn, inp, sec)
        if not ok: return ("END " if end else "CON ") + msg
        if sec:
            code = "%06d" % secrets.randbelow(10**6)
            q("INSERT OR REPLACE INTO otps VALUES(?,?,?,0)", (msisdn, code, time.time() + 120), commit=True)
            q("INSERT INTO outbox(ts,msisdn,text) VALUES(?,?,?)", (time.time(), msisdn, f"Your bank OTP is {code}. Valid 2 min."), commit=True)
            st["step"] = "tr_otp"
        else:
            c["pin_ok"] = True; c["ev5"] = msg; st["step"] = "tr_confirm"
            return f"CON PIN accepted [{msg}]\n" + screen(st)[4:]   # S5 token shown as soon as the PIN is guessed
        return screen(st)
    if step == "tr_otp":
        o = q("SELECT * FROM otps WHERE msisdn=?", (msisdn,), one=True)
        if not o or o["exp"] < time.time() or o["tries"] >= 3: return "END OTP expired or too many attempts"
        q("UPDATE otps SET tries=tries+1 WHERE msisdn=?", (msisdn,), commit=True)
        if not hmac.compare_digest(o["code"], inp): return "CON Wrong OTP\n" + screen(st)[4:]
        q("DELETE FROM otps WHERE msisdn=?", (msisdn,), commit=True); st["step"] = "tr_confirm"; return screen(st)
    if step == "tr_confirm":
        if inp == "2": st["step"] = "root"; st["ctx"] = {}; return "CON Cancelled\n" + MENU[4:]
        if inp != "1": return screen(st)
        ref = c["ref"] if sec else "T%d" % int(time.time() * 1000)
        r = bk("POST", "/transfer", json={"src": msisdn, "dest": c["dest"], "amount": c["amt"], "ref": ref})
        if r.status_code != 200: return "END Failed: " + r.json().get("error", "error")
        if sec:
            st["step"] = "root"; st["ctx"] = {}; return "CON Transfer done.\n" + MENU[4:]
        c["n"] = c.get("n", 0) + 1; tags = []                      # vulnerable: state NOT consumed => replayable
        if c["n"] > 1: tags.append(ev(3))
        if c["amt"] < 0: tags.append(ev(6))
        if swapped(msisdn): tags.append(ev(7))
        if not c.get("pin_ok"): tags.append(ev(2))
        if c.get("ev5"): tags.append(c["ev5"])
        return f"CON Sent NGN {c['amt']} (#{c['n']}) [{' '.join(tags)}]\n1 Send again\n2 Done"
    if step == "stmt":
        qs = "" if inp in ("", "0") else inp
        if sec and not re.fullmatch(r"[A-Za-z0-9]{0,16}", qs): return "CON Invalid reference\n" + screen(st)[4:]
        r = bk("GET", "/statement", params={"msisdn": msisdn, "q": qs})
        j = r.json(); st["step"] = "root"
        if r.status_code != 200: return "END " + j.get("error", "error") + (" | " + j["query"] if j.get("query") else "")
        lines = [f"{x['ref']} {x['amount']} {x['peer'][-4:]} {x['memo']}" for x in j["rows"]] or ["No entries"]
        return "END " + "\n".join(lines)
    return "END Error"

@app.post("/ussd")
def ussd():
    f = request.form; inp = f.get("input", "").strip(); sid = f.get("sessionId", "").strip()
    sec = mode() == "secure"; now = time.time()
    if sec:
        msisdn = verify_gw()
        if not msisdn: return plain("END Unauthorised gateway identity", 401)
    else:
        msisdn = request.headers.get("X-MSISDN") or f.get("msisdn")   # trusts client-supplied header (flaw)
        if not msisdn: return plain("END No subscriber identity")
    if not q("SELECT 1 FROM subscribers WHERE msisdn=?", (msisdn,), one=True): return plain("END Unknown subscriber")
    row = q("SELECT * FROM sessions WHERE id=?", (sid,), one=True) if sid else None
    fresh = hijack = stale = False
    if sec:
        if sid and not row: return plain("END Session invalid")
        if row and (row["msisdn"] != msisdn or now - row["last"] > IDLE or now - row["created"] > ABS):
            if row["msisdn"] != msisdn: log(f"ALERT session/identity mismatch msisdn={msisdn}")
            q("DELETE FROM sessions WHERE id=?", (sid,), commit=True); return plain("END Session expired. Dial again.")
        if not row:   # one concurrent session per subscriber; new session invalidates old
            q("DELETE FROM sessions WHERE msisdn=?", (msisdn,), commit=True)
            sid = secrets.token_urlsafe(24); st = {"step": "pin", "authed": False, "ctx": {}}
            create_session(sid, msisdn, st); fresh = True
        else: st = json.loads(row["state"])
    else:
        if row:
            if f.get("exp"):   # client-controlled expiry (flaw)
                try: q("UPDATE sessions SET exp=? WHERE id=?", (float(f["exp"]), sid), commit=True)
                except ValueError: pass
                row = q("SELECT * FROM sessions WHERE id=?", (sid,), one=True)
            if row["exp"] and now > row["exp"]: return plain("END Session expired")
            stale = bool(f.get("exp")) or (now - row["last"] > IDLE)   # S4: expiry client-controlled / not enforced
            hijack = row["msisdn"] != msisdn                          # S3: session not bound to caller identity
            msisdn = row["msisdn"]   # session over-trusted: not bound to caller identity (flaw)
            st = json.loads(row["state"])
        else:
            sid = sid or "S%d" % (1000 + seq())   # predictable IDs; client-chosen IDs accepted (flaw)
            st = {"step": "root", "authed": False, "ctx": {}}; create_session(sid, msisdn, st); fresh = True
    text = screen(st) if fresh else logic(msisdn, st, inp, sec)
    if hijack or stale: text += " [" + " ".join(([ev(3)] if hijack else []) + ([ev(4)] if stale else [])) + "]"
    if st.pop("_rotate", False):   # rotate session ID after authentication
        q("DELETE FROM sessions WHERE id=?", (sid,), commit=True); sid = secrets.token_urlsafe(24); create_session(sid, msisdn, st)
    q("UPDATE sessions SET state=?, last=? WHERE id=?", (json.dumps(st), time.time(), sid), commit=True)
    if text.startswith("END"): q("DELETE FROM sessions WHERE id=?", (sid,), commit=True) if sec else None
    return plain(text, sid=sid)

# ---------- SIM-swap registry (scenario 7) ----------
@app.post("/registry/simswap")
def simswap():
    m = (request.get_json(force=True, silent=True) or {}).get("msisdn", "")
    if not q("SELECT 1 FROM subscribers WHERE msisdn=?", (m,), one=True): return jsonify(error="unknown"), 404
    q("UPDATE subscribers SET sim_changed=? WHERE msisdn=?", (time.time(), m), commit=True)
    log(f"registry: SIM change event for {m}")
    return jsonify(ok=True, msisdn=m, window_seconds=SWAP_WINDOW)

# ---------- MO-SMS / SMPP simulator (scenario 10) ----------
def sms_out(m, t): q("INSERT INTO outbox(ts,msisdn,text) VALUES(?,?,?)", (time.time(), m, t), commit=True)

@app.post("/smpp/bind")
def smpp_bind():
    j = request.get_json(force=True, silent=True) or {}
    if mode() != "secure": return jsonify(note="no bind required in this profile")
    k = "bind:" + request.remote_addr
    if q("SELECT COUNT(*) c FROM rate WHERE k=? AND ts>?", (k, time.time() - 60), one=True)["c"] >= 5:
        return jsonify(error="rate limited"), 429
    q("INSERT INTO rate VALUES(?,?)", (k, time.time()), commit=True)
    if j.get("system_id") == "aggr01" and hmac.compare_digest(str(j.get("password", "")), SMPP_PASS):
        tok = secrets.token_urlsafe(16); q("INSERT INTO binds VALUES(?,?)", (tok, time.time() + 300), commit=True)
        return jsonify(bind_token=tok, expires_in=300)
    log(f"ALERT failed SMPP bind from {request.remote_addr}"); return jsonify(error="bind failed"), 401

@app.post("/smpp/mo")
def smpp_mo():
    j = request.get_json(force=True, silent=True) or {}
    sec = mode() == "secure"; src, mid, body = str(j.get("source_addr", "")), str(j.get("message_id", "")), str(j.get("short_message", ""))
    if sec:
        tok = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not q("SELECT 1 FROM binds WHERE token=? AND exp>?", (tok, time.time()), one=True): return jsonify(error="not bound"), 401
        if not mid or not re.fullmatch(r"234\d{10}", src) or not q("SELECT 1 FROM subscribers WHERE msisdn=?", (src,), one=True) or j.get("dest_addr") != "32123":
            log(f"ALERT malformed MO-SMS src={src[:15]}"); return jsonify(error="rejected"), 400
        if q("SELECT 1 FROM seen WHERE msg_id=?", (mid,), one=True): return jsonify(status="DUPLICATE_IGNORED")
        if q("SELECT COUNT(*) c FROM rate WHERE k=? AND ts>?", ("mo:" + src, time.time() - 60), one=True)["c"] >= 10:
            return jsonify(error="rate limited"), 429
        q("INSERT INTO rate VALUES(?,?)", ("mo:" + src, time.time()), commit=True)
    n = (q("SELECT COUNT(*) c FROM seen WHERE msg_id=?", (mid,), one=True)["c"] or 0) + 1
    q("INSERT INTO seen VALUES(?,?)", (mid, n), commit=True)
    q("INSERT INTO billing(src,msg_id) VALUES(?,?)", (src, mid), commit=True)
    t = body.upper().split(); res = "UNKNOWN_COMMAND"
    try:
        if t[:1] == ["BAL"]:
            sms_out(src, f"Balance NGN {bk('GET', f'/balance/{src}').json().get('balance')}"); res = "BAL_SENT"
        elif t[:1] == ["PAY"] and len(t) == 3 and not sec:
            r = bk("POST", "/transfer", json={"src": src, "dest": t[1], "amount": int(t[2]), "ref": "M%d" % int(time.time() * 1000)}); res = "PAY_%d" % r.status_code
        elif t[:1] == ["PAY"]:
            sms_out(src, "SMS payments are disabled. Use USSD with step-up."); res = "PAY_DISABLED"
    except Exception as e: res = f"ERR {e!r}"
    log(f"MO-SMS src={src} id={mid} res={res}")
    out = {"status": "PROCESSED", "result": res, "times_seen": n}
    if not sec: out["evidence"] = ev(10)
    return jsonify(out)

# ---------- signalling analysis (scenario 9) ----------
@app.get("/lab/signalling/events.csv")
def sig_events(): return Response(open(f"{DATA}/events.csv").read(), mimetype="text/csv")

@app.get("/lab/signalling/peers.json")
def sig_peers(): return Response(open(f"{DATA}/peers.json").read(), mimetype="application/json")

@app.post("/lab/signalling/submit")
def sig_submit():
    ids = set((request.get_json(force=True, silent=True) or {}).get("event_ids", []))
    key = set(json.load(open(f"{DATA}/.sig_key.json")))
    tp = len(ids & key); prec = tp / len(ids) if ids else 0; rec = tp / len(key)
    out = {"precision": round(prec, 2), "recall": round(rec, 2), "hint": "need both >= 0.8"}
    if prec >= .8 and rec >= .8: out["evidence"] = ev(9)
    return jsonify(out)

# ---------- lab helpers ----------
@app.get("/lab/logs")
def lab_logs():
    try: return plain("".join(open(f"{DATA}/app.log").readlines()[-80:]))
    except Exception: return plain("")

@app.get("/lab/wire")
def lab_wire():
    try: return plain("".join(open(f"{DATA}/wire.log").readlines()[-40:]))
    except Exception: return plain("")

@app.get("/lab/outbox")
def lab_outbox():
    m = request.args.get("msisdn", MALLORY)
    return jsonify([dict(r) for r in q("SELECT ts,msisdn,text FROM outbox WHERE msisdn=? ORDER BY id DESC LIMIT 10", (m,))])

@app.get("/lab/status")
def lab_status():
    return jsonify(lab_id=LAB_ID, profile=mode(), timers={"idle": IDLE, "abs": ABS, "swap_window": SWAP_WINDOW}, billing_rows=q("SELECT COUNT(*) c FROM billing", one=True)["c"],
                   pin_attempts_used={r["msisdn"]: r["pin_tries"] for r in q("SELECT msisdn,pin_tries FROM subscribers")},
                   subscribers=[{"msisdn": r["msisdn"], "name": r["name"]} for r in q("SELECT msisdn,name FROM subscribers")])

@app.post("/admin/mode")
def admin_mode():
    if not admin_only(): return jsonify(error="forbidden"), 403
    m = (request.get_json(force=True, silent=True) or {}).get("mode")
    if m not in ("vulnerable", "secure"): return jsonify(error="mode must be vulnerable|secure"), 400
    open(f"{DATA}/mode", "w").write(m); log(f"profile set to {m}"); return jsonify(profile=m)

@app.post("/admin/reset")
def admin_reset():
    if not admin_only(): return jsonify(error="forbidden"), 403
    open(f"{DATA}/epoch", "w").write(str(time.time())); sync_epoch()
    for fn in ("app.log", "wire.log"):
        try: os.remove(f"{DATA}/{fn}")
        except FileNotFoundError: pass
    return jsonify(ok=True)

HANDSET = """<!doctype html><meta name=viewport content="width=device-width,initial-scale=1"><title>USSD handset</title>
<style>body{font:16px system-ui;max-width:26rem;margin:2rem auto;padding:0 1rem}pre{background:#10261a;color:#9bf5b4;padding:1rem;min-height:10rem;white-space:pre-wrap;border-radius:6px;font:14px ui-monospace,monospace}
input{font:inherit;padding:.5rem;width:55%}button{font:inherit;padding:.5rem .8rem}small{color:#555}</style>
<h3>USSD handset simulator</h3><small>SIM: Mallory +2348000000009 &middot; profile: <b id=p></b></small>
<pre id=s>Press Dial to start a session.</pre>
<input id=i placeholder="your reply" autocomplete=off> <button onclick="go(document.getElementById('i').value)">Send</button> <button onclick="sid='';go('')">Dial *384#</button>
<script>let sid="";
async function go(v){const r=await fetch("/gw/ussd",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({input:v,sessionId:sid})});
const j=await r.json();sid=j.sessionId||sid;document.getElementById("s").textContent=j.screen+"\\n\\n[session "+sid+"]";document.getElementById("i").value="";if(j.end)sid="";}
fetch("/lab/status").then(r=>r.json()).then(j=>document.getElementById("p").textContent=j.profile);</script>"""

@app.get("/")
def home(): return Response(HANDSET, mimetype="text/html")

if __name__ == "__main__":
    if not os.path.exists(f"{DATA}/mode"): open(f"{DATA}/mode", "w").write("vulnerable")
    sync_epoch()
    app.run("0.0.0.0", PORT, threaded=True)
