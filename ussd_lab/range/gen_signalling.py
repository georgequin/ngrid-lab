"""Generate synthetic SS7/Diameter event records for scenario 9. No live signalling anywhere."""
import random, csv, json, os
from datetime import datetime, timedelta
from common import DATA, LAB_ID
rnd = random.Random(LAB_ID)
HOME_GT, HOME_REALM = "234800100100", "epc.mnc001.mcc234.3gppnetwork.org"
PARTNERS = {"gt": ["447700100200", "27820001000", "33600100300"],
            "realm": ["epc.mnc010.mcc234.3gppnetwork.org", "epc.mnc002.mcc655.3gppnetwork.org"]}
SUBS = {"2348000000001": "234001000000001", "2348000000002": "234001000000002", "2348000000003": "234001000000003"}
t0 = datetime(2026, 11, 17, 6, 0, 0)
rows = []
def add(sec, proto, msg, src, dst, subj, detail, bad=False):
    rows.append(dict(ts=(t0 + timedelta(seconds=sec)).isoformat(), proto=proto, msg=msg, src=src, dst=dst, subject=subj, detail=detail, bad=bad))
for _ in range(300):
    m, imsi = rnd.choice(list(SUBS.items())); s = rnd.randint(0, 36000)
    k = rnd.choice(["sri", "ul", "sai", "mt", "air", "clr"])
    if k == "sri": add(s, "MAP", "SendRoutingInfoForSM", HOME_GT, HOME_GT, m, "home SMSC lookup")
    elif k == "mt": add(s, "MAP", "MT-ForwardSM", HOME_GT, rnd.choice(PARTNERS["gt"]), m, "SMS delivery")
    elif k == "ul": add(s, "MAP", "UpdateLocation", rnd.choice(PARTNERS["gt"]), HOME_GT, imsi, "partner VLR, subscriber roaming")
    elif k == "sai": add(s, "MAP", "SendAuthenticationInfo", rnd.choice(PARTNERS["gt"]), HOME_GT, imsi, "partner auth vectors, 1 request")
    elif k == "air": add(s, "DIAMETER", "AIR", rnd.choice(PARTNERS["realm"]), HOME_REALM, imsi, "roaming auth, 1 request")
    else: add(s, "DIAMETER", "CLR", HOME_REALM, rnd.choice(PARTNERS["realm"]), imsi, "cancel location after move")
a, b, c = list(SUBS)
base = rnd.randint(9000, 20000)
for i in range(4): add(base + i * 25, "MAP", "SendRoutingInfoForSM", "79990001234", HOME_GT, a, "repeated lookup from unlisted GT", True)
for i in range(2): add(base + 4000 + i * 40, "MAP", "AnyTimeInterrogation", "8613900000000", HOME_GT, c, "location query from non-partner GT", True)
add(base + 8000, "MAP", "UpdateLocation", "4479999999", HOME_GT, SUBS[b], "unlisted GT claims subscriber; subscriber last seen at home", True)
for i in range(2): add(base + 9000 + i * 30, "DIAMETER", "ULR", "epc.mnc099.mcc999.3gppnetwork.org", HOME_REALM, SUBS[a], "realm not in allow-list", True)
add(base + 12000, "MAP", "ProvideSubscriberInfo", "5511900000000", HOME_GT, c, "location/state probe from non-partner GT", True)
rows.sort(key=lambda r: r["ts"])
key = []
with open(f"{DATA}/events.csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(["event_id", "ts", "proto", "msg_type", "source_peer", "dest_peer", "subject", "detail"])
    for i, r in enumerate(rows, 1):
        eid = "E%04d" % i
        if r["bad"]: key.append(eid)
        w.writerow([eid, r["ts"], r["proto"], r["msg"], r["src"], r["dst"], r["subject"], r["detail"].replace("repeated lookup from unlisted GT", "lookup").replace("location query from non-partner GT", "query").replace("unlisted GT claims subscriber; subscriber last seen at home", "update").replace("realm not in allow-list", "ulr").replace("location/state probe from non-partner GT", "probe")])
json.dump({"home_gt": HOME_GT, "home_realm": HOME_REALM, "partner_gts": PARTNERS["gt"], "partner_realms": PARTNERS["realm"]}, open(f"{DATA}/peers.json", "w"), indent=1)
json.dump(key, open(f"{DATA}/.sig_key.json", "w"))
os.chmod(f"{DATA}/.sig_key.json", 0o600)
