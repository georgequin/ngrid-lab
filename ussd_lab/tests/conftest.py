"""Test harness.
Default (LAB_MODE=process): builds both environments from the real bundles (student bundle for participants)
and runs each range instance as its own process with its own data dir, secrets, ports and backend ports.
This exercises the exact app code but not Docker. Against a real compose stack: LAB_MODE=external.
  external needs: local/setup.sh with TEST_TIMERS=1, then 'local/labctl_local.sh <env> up' for both envs."""
import os, subprocess, sys, time, tarfile, shutil, pathlib, socket, json
import pytest, requests

ROOT = pathlib.Path(__file__).resolve().parents[1]
RUN = pathlib.Path(os.environ.get("LAB_RUN_DIR", "/tmp/ussd-lab-run"))
MODE = os.environ.get("LAB_MODE", "process")
P_BASE, P_N = 8000, 10
I_BASE, I_N = 8100, 3
GW = {"idle": 3, "abs": 8, "swap_window": 5}

class Inst:
    def __init__(self, env, i, base, token, datadir, secret=""):
        self.env, self.i, self.port, self.token, self.data = env, i, base + i, token, datadir
        self.secret = secret
        self.url = f"http://127.0.0.1:{self.port}"
        self.bk_plain, self.bk_tls = 19000 + (self.port - 8000) * 2, 19001 + (self.port - 8000) * 2
    # ---- raw helpers ----
    def get(self, path, **kw): return requests.get(self.url + path, timeout=10, **kw)
    def post(self, path, **kw): return requests.post(self.url + path, timeout=10, **kw)
    def admin(self, path, body=None, token=None):
        h = {"X-Admin-Token": token if token is not None else self.token}
        return requests.post(self.url + path, json=body, headers=h, timeout=10)
    def set_mode(self, m): r = self.admin("/admin/mode", {"mode": m}); assert r.status_code == 200, r.text
    def reset(self): assert self.admin("/admin/reset").status_code == 200
    def fresh(self, mode):
        self.set_mode(mode); self.reset(); time.sleep(0.2); return self
    def status(self): return self.get("/lab/status").json()
    # ---- USSD helpers ----
    def gw(self, inp="", sid="", hdr=None, **extra):
        j = requests.post(self.url + "/gw/ussd", json={"input": inp, "sessionId": sid, **extra}, headers=hdr or {}, timeout=10).json()
        return j["sessionId"], j["screen"]
    def spoof(self, victim): return {"X-MSISDN": victim}
    def login(self):
        s, _ = self.gw(); s, o = self.gw("2580", s); assert o.startswith("CON My Bank"), o; return s
    def flow(self, steps, sid="", hdr=None):
        out = ""
        for st in steps: sid, out = self.gw(st, sid, hdr)
        return sid, out
    def sigkey(self):
        p = self.data / ".sig_key.json"
        return json.load(open(p)) if p.exists() else None

def wait_port(port, t=40):
    end = time.time() + t
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.5): return
        except OSError: time.sleep(0.3)
    raise RuntimeError(f"port {port} not up")

def build_envs():
    subprocess.run([str(ROOT / "scripts/package.sh")], check=True, capture_output=True)
    if RUN.exists(): shutil.rmtree(RUN)
    for env, bundle in (("instructor", "instructor"), ("participant", "student")):
        (RUN / env).mkdir(parents=True)
        with tarfile.open(ROOT / f"dist/{bundle}.tar.gz") as t: t.extractall(RUN / env, filter="data")

@pytest.fixture(scope="session")
def envs():
    if MODE == "external":
        def rd(e): return dict(l.strip().split("=", 1) for l in open(ROOT / f"local/run/{e}/.env") if "=" in l)
        pe, ie = rd("participant"), rd("instructor")
        P = [Inst("participant", i, P_BASE, pe["ADMIN_TOKEN"], ROOT / f"local/run/participant/data/p{i}", f'{pe["LAB_SECRET"]}-p{i}') for i in range(1, P_N + 1)]
        I = [Inst("instructor", i, I_BASE, ie["ADMIN_TOKEN"], ROOT / f"local/run/instructor/data/p{i}", f'{ie["LAB_SECRET"]}-p{i}') for i in range(1, I_N + 1)]
        yield dict(P=P, I=I, student_dir=ROOT / "local/run/participant", instr_dir=ROOT / "local/run/instructor", process=False); return
    build_envs()
    certs = RUN / "certs"
    subprocess.run(["sh", str(ROOT / "range/gen_certs.sh")], env={**os.environ, "CERT_DIR": str(certs)}, check=True)
    procs, P, I = [], [], []
    for env, base, n, lst, tok in (("participant", P_BASE, P_N, P, "ptok-" + os.urandom(6).hex()), ("instructor", I_BASE, I_N, I, "itok-" + os.urandom(6).hex())):
        for i in range(1, n + 1):
            d = RUN / env / "data" / f"p{i}"; d.mkdir(parents=True)
            x = Inst(env, i, base, tok, d, f"{env}-secret-p{i}"); lst.append(x)
            e = {**os.environ, "LAB_DATA": str(d), "LAB_ID": f"{env}-p{i}", "LAB_SECRET": f"{env}-secret-p{i}", "ADMIN_TOKEN": tok, "PORT": str(x.port),
                 "BACKEND_PLAIN_PORT": str(x.bk_plain), "BACKEND_TLS_PORT": str(x.bk_tls), "CERT_DIR": str(certs), "IDLE": "3", "ABS": "8", "SWAP_WINDOW": "5"}
            (d / "mode").write_text("vulnerable")
            cwd = RUN / env / "range"
            subprocess.run([sys.executable, "gen_signalling.py"], cwd=cwd, env=e, check=True)
            procs.append(subprocess.Popen([sys.executable, "backend.py"], cwd=cwd, env=e, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            procs.append(subprocess.Popen([sys.executable, "app.py"], cwd=cwd, env=e, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    for x in P + I: wait_port(x.port)
    yield dict(P=P, I=I, student_dir=RUN / "participant", instr_dir=RUN / "instructor", process=True, certs=certs)
    for p in procs: p.terminate()

@pytest.fixture
def p1(envs): return envs["P"][0]
@pytest.fixture
def vul(envs): return envs["P"][0].fresh("vulnerable")
@pytest.fixture
def sec(envs):
    return envs["P"][0].fresh("secure")
@pytest.fixture
def short(envs):
    if envs["P"][0].status()["timers"]["idle"] > 10: pytest.skip("timing tests need short timers (TEST_TIMERS=1 local/setup.sh)")
@pytest.fixture
def needs_process(envs):
    if not envs["process"]: pytest.skip("needs access to container-internal ports; process harness only")
