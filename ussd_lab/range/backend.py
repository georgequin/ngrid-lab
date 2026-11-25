"""Mock core-banking backend. Owns balances/transactions. Listens on 9000 (plain) and 9443 (mTLS)."""
import os, ssl, sqlite3, threading, time
from flask import Flask, request, jsonify
from werkzeug.serving import make_server
from common import *

DB = f"{DATA}/backend.db"
app = Flask(__name__)
_seen_epoch = [None]

def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c

def init():
    if os.path.exists(DB): os.remove(DB)
    c = db()
    c.executescript("""
    CREATE TABLE accounts(msisdn TEXT PRIMARY KEY, balance INTEGER);
    CREATE TABLE tx(id INTEGER PRIMARY KEY AUTOINCREMENT, ref TEXT UNIQUE, msisdn TEXT, peer TEXT, amount INTEGER, memo TEXT);
    """)
    c.executemany("INSERT INTO accounts VALUES(?,?)", [("2348000000001",150000),("2348000000002",90000),("2348000000003",25000),("2348000000009",5000)])
    c.executemany("INSERT INTO tx(ref,msisdn,peer,amount,memo) VALUES(?,?,?,?,?)", [
        ("SEED-A1","2348000000001","2348000000002",-5000,"rent share"),
        ("SEED-A2","2348000000001","2348000000003",-2500,"lunch"),
        ("SEED-B1","2348000000002","2348000000001",5000,"rent share"),
        ("SEED-C1","2348000000003","2348000000001",2500,"lunch"),
        ("SEED-C2","2348000000003","2348000000002",-1000,"internal note: " + ev(6)),
    ])
    c.commit(); c.close()

@app.before_request
def gate():
    if _seen_epoch[0] != epoch():       # instructor reset => re-seed
        _seen_epoch[0] = epoch(); init()
    secure_port = request.environ.get("SERVER_PORT") == str(BK_TLS)
    if mode() == "secure" and not secure_port:
        return jsonify(error="plaintext hop disabled; use mTLS"), 403
    if request.headers.get("X-Api-Key") != BK_KEY:
        return jsonify(error="bad key"), 401
    body = request.get_data(as_text=True)
    if secure_port:
        wire(f"[TLS1.3 mTLS] {len(body)+240} bytes of encrypted application data - nothing readable at this boundary")
    else:   # what a tap on the plaintext hop sees
        wire(f"{request.method} {request.full_path} | X-Api-Key: {BK_KEY} | body={body} | {ev(8)}")

@app.get("/balance/<m>")
def balance(m):
    r = db().execute("SELECT balance FROM accounts WHERE msisdn=?", (m,)).fetchone()
    return (jsonify(balance=r["balance"]), 200) if r else (jsonify(error="no account"), 404)

@app.post("/transfer")
def transfer():
    j = request.get_json(force=True); sec = mode() == "secure"
    src, dest, amt, ref = j["src"], j["dest"], j["amount"], j["ref"]
    if sec and (not isinstance(amt, int) or amt <= 0):
        return jsonify(error="invalid amount"), 400
    c = db()
    a = c.execute("SELECT balance FROM accounts WHERE msisdn=?", (src,)).fetchone()
    d = c.execute("SELECT balance FROM accounts WHERE msisdn=?", (dest,)).fetchone()
    if not a or not d: return jsonify(error="unknown account"), 404
    if a["balance"] < amt: return jsonify(error="insufficient funds"), 400   # negative amounts slip through in vulnerable mode
    try:
        c.execute("INSERT INTO tx(ref,msisdn,peer,amount,memo) VALUES(?,?,?,?,?)", (ref, src, dest, -amt, "ussd transfer"))
    except sqlite3.IntegrityError:
        return jsonify(error="duplicate ref (idempotent replay rejected)"), 409
    c.execute("UPDATE accounts SET balance=balance-? WHERE msisdn=?", (amt, src))
    c.execute("UPDATE accounts SET balance=balance+? WHERE msisdn=?", (amt, dest))
    c.commit()
    return jsonify(ok=True, ref=ref, balance=a["balance"] - amt)

@app.get("/statement")
def statement():
    m, qs = request.args.get("msisdn", ""), request.args.get("q", "")
    c = db()
    try:
        if mode() == "secure":
            rows = c.execute("SELECT ref,peer,amount,memo FROM tx WHERE msisdn=? AND ref LIKE ? ORDER BY id DESC LIMIT 5", (m, f"%{qs}%")).fetchall()
        else:   # DELIBERATELY UNSAFE: string-built SQL against the isolated synthetic dataset
            sql = f"SELECT ref,peer,amount,memo FROM tx WHERE msisdn='{m}' AND ref LIKE '%{qs}%' ORDER BY id DESC LIMIT 20"
            rows = c.execute(sql).fetchall()
        return jsonify(rows=[dict(r) for r in rows])
    except sqlite3.Error as e:
        return jsonify(error=f"SQL error: {e}", query=sql if mode() != "secure" else None), 500

def serve(port, ctx=None):
    make_server("0.0.0.0", port, app, threaded=True, ssl_context=ctx).serve_forever()

if __name__ == "__main__":
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(f"{CERT_DIR}/server.crt", f"{CERT_DIR}/server.key")
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(f"{CERT_DIR}/ca.crt")
    threading.Thread(target=serve, args=(BK_TLS, ctx), daemon=True).start()
    serve(BK_PLAIN)
