import re, time, hmac, hashlib, secrets, requests
ALICE, BOB, CAROL, MAL = "2348000000001", "2348000000002", "2348000000003", "2348000000009"
def tok(text, n): m = re.search(rf"EVID-S{n}-[0-9a-f]{{8}}", text or ""); return m.group(0) if m else None
def otp_from_outbox(x):
    return x.get("/lab/outbox").json()[0]["text"].split()[4].rstrip(".")
def secure_transfer_to_confirm(x, dest=ALICE, amt="100"):
    s = x.login(); x.gw("2", s); x.gw(dest, s); x.gw(amt, s); x.gw("2580", s)
    s, o = x.gw(otp_from_outbox(x), s); return s, o
def gw_key(secret): return hashlib.sha256(f"gw|{secret}".encode()).hexdigest()[:32].encode()
def bk_key(secret): return hashlib.sha256(f"bk|{secret}".encode()).hexdigest()[:32]
def signed_headers(key, msisdn=MAL):
    ts, n = str(int(time.time())), secrets.token_hex(8)
    return {"X-GW-MSISDN": msisdn, "X-GW-TS": ts, "X-GW-NONCE": n, "X-GW-SIG": hmac.new(key, f"{msisdn}|{ts}|{n}".encode(), hashlib.sha256).hexdigest()}
