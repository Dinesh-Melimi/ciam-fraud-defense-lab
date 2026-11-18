"""Generate synthetic login and checkout telemetry with embedded attacks."""
import random, sqlite3, hashlib
from datetime import datetime, timedelta

COUNTRIES = ["US", "US", "US", "US", "CA", "MX"]
ATTACK_ASN = 64512  # residential-proxy style network used by the attacker


def _h(s):
    return hashlib.sha256(s.encode()).hexdigest()[:16]


def build(db_path="fraudlab.db", seed=7, start=None):
    rnd = random.Random(seed)
    start = start or datetime(2026, 11, 1, 8, 0)
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.executescript(open(__file__.replace("generate.py", "schema.sql")).read())
    users = [f"user{i}@example.com" for i in range(400)]
    home = {u: rnd.choice(COUNTRIES) for u in users}
    dev = {u: _h("dev" + u) for u in users}
    logins, txns, changes = [], [], []

    # 1) normal customer activity
    for _ in range(3000):
        u = rnd.choice(users)
        ts = start + timedelta(minutes=rnd.randint(0, 60 * 24 * 3))
        ok = rnd.random() > 0.05
        logins.append((ts.isoformat(), u, f"10.0.{rnd.randint(0,255)}.{rnd.randint(1,254)}",
                       rnd.randint(1000, 1100), dev[u], home[u], "SUCCESS" if ok else "FAIL", 1))
        if ok and rnd.random() < 0.3:
            txns.append((ts.isoformat(), u, dev[u], _h("card" + u), "411111",
                         round(rnd.uniform(25, 180), 2), "APPROVED", "web"))

    # 2) credential stuffing: few devices, many accounts, ~1% success
    t0 = start + timedelta(days=1, hours=2)
    bots = [_h(f"bot{i}") for i in range(4)]
    for i in range(1200):
        u = rnd.choice(users) if rnd.random() < 0.7 else f"ghost{i}@example.com"
        ts = t0 + timedelta(seconds=i * 2)
        ok = u in home and rnd.random() < 0.012
        logins.append((ts.isoformat(), u, f"172.16.{rnd.randint(0,255)}.{rnd.randint(1,254)}",
                       ATTACK_ASN, rnd.choice(bots), "US", "SUCCESS" if ok else "FAIL", 0))
        if ok:  # account takeover follow-through
            changes.append(((ts + timedelta(minutes=4)).isoformat(), u, "EMAIL"))

    # 3) card testing: one device, many cards, tiny amounts, mostly declined
    t1 = start + timedelta(days=2, hours=3)
    for i in range(150):
        ts = t1 + timedelta(seconds=i * 15)
        txns.append((ts.isoformat(), "guest", _h("tester"), _h(f"stolen{i}"), "542418",
                     round(rnd.uniform(0.5, 2.0), 2), "APPROVED" if rnd.random() < 0.15 else "DECLINED", "web"))

    cur.executemany("INSERT INTO login_events VALUES (?,?,?,?,?,?,?,?)", logins)
    cur.executemany("INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?)", txns)
    cur.executemany("INSERT INTO account_changes VALUES (?,?,?)", changes)
    con.commit()
    return con
