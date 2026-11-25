import os, time, hmac, hashlib
DATA = os.environ.get("LAB_DATA", "/data")
LAB_ID = os.environ.get("LAB_ID", "lab")
LAB_SECRET = os.environ.get("LAB_SECRET", "change-me")
BK_PLAIN = int(os.environ.get("BACKEND_PLAIN_PORT", "9000"))
BK_TLS = int(os.environ.get("BACKEND_TLS_PORT", "9443"))
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
def derived(label):
    """Per-instance keys derived from LAB_SECRET, so no shipped default key works on any instance."""
    return hashlib.sha256(f"{label}|{LAB_SECRET}".encode()).hexdigest()[:32]
GW_KEY = os.environ.get("GW_KEY") or derived("gw")
BK_KEY = os.environ.get("BACKEND_KEY") or derived("bk")
os.makedirs(DATA, exist_ok=True)

def mode():
    try: return open(f"{DATA}/mode").read().strip()
    except Exception: return "vulnerable"

def epoch():
    try: return open(f"{DATA}/epoch").read().strip()
    except Exception: return "0"

def ev(n):
    """Evidence token: unique per lab instance and scenario. Shown only when a flaw is demonstrated."""
    return "EVID-S%d-%s" % (n, hmac.new(LAB_SECRET.encode(), f"{LAB_ID}:{n}".encode(), hashlib.sha256).hexdigest()[:8])

def log(line):
    with open(f"{DATA}/app.log", "a") as f:
        f.write(f"{time.strftime('%H:%M:%S')} [{mode()}] {line}\n")

def wire(line):
    with open(f"{DATA}/wire.log", "a") as f:
        f.write(f"{time.strftime('%H:%M:%S')} {line}\n")
