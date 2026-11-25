"""Req 6: handset UI and /gw/ussd work through an HTTP proxy (Burp stand-in) and header tampering via the proxy works."""
import os, threading, socket, requests, pytest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from helpers import *

class Proxy(BaseHTTPRequestHandler):
    log, tamper = [], {}
    def _fwd(self):
        n = int(self.headers.get("Content-Length") or 0); body = self.rfile.read(n) if n else None
        hdr = {k: v for k, v in self.headers.items() if k.lower() not in ("proxy-connection", "connection", "host", "content-length")}
        hdr.update(Proxy.tamper)                                             # what an analyst does in Burp Proxy > Intercept
        Proxy.log.append((self.command, self.path, body))
        s = requests.Session(); s.trust_env = False
        r = s.request(self.command, self.path, data=body, headers=hdr, allow_redirects=False, timeout=10)
        self.send_response(r.status_code)
        for k, v in r.headers.items():
            if k.lower() not in ("transfer-encoding", "connection", "content-length", "content-encoding"): self.send_header(k, v)
        self.send_header("Content-Length", str(len(r.content))); self.end_headers(); self.wfile.write(r.content)
    do_GET = do_POST = _fwd
    def log_message(self, *a): pass

@pytest.fixture
def proxy():
    port = int(os.environ.get("PROXY_PORT", "8080"))
    try: srv = ThreadingHTTPServer(("127.0.0.1", port), Proxy)
    except OSError: srv = ThreadingHTTPServer(("127.0.0.1", 0), Proxy)       # 8080 busy: any free port
    threading.Thread(target=srv.serve_forever, daemon=True).start(); Proxy.log.clear(); Proxy.tamper = {}
    yield {"http": f"http://127.0.0.1:{srv.server_address[1]}"}
    srv.shutdown()

def via(x, proxies, inp, sid=""):
    j = requests.post(x.url + "/gw/ussd", json={"input": inp, "sessionId": sid}, proxies=proxies, timeout=10).json(); return j["sessionId"], j["screen"]

def test_handset_ui_and_gateway_work_through_proxy(vul, proxy):
    r = requests.get(vul.url + "/", proxies=proxy, timeout=10); assert r.status_code == 200 and "USSD handset simulator" in r.text
    s, o = via(vul, proxy, ""); assert "My Bank" in o
    assert any(p.endswith("/gw/ussd") and b and b'"input"' in b for _, p, b in Proxy.log)    # request body visible and editable in the proxy

def test_header_tampering_in_proxy_reproduces_scenario_1(vul, proxy):
    Proxy.tamper = {"X-MSISDN": ALICE}
    s, _ = via(vul, proxy, ""); _, o = via(vul, proxy, "1", s); assert "150000" in o and tok(o, 1), o

def test_same_tampering_fails_in_secure_profile(sec, proxy):
    Proxy.tamper = {"X-MSISDN": ALICE}
    s, o = via(sec, proxy, ""); assert "Enter PIN" in o
    s, _ = via(sec, proxy, "2580", s); _, o = via(sec, proxy, "1", s); assert "NGN 5000" in o and "150000" not in o
