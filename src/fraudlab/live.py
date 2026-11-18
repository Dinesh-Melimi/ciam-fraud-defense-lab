"""Stream synthetic traffic event by event and raise detections in real time."""
import random, time, hashlib
from collections import defaultdict, deque
from .risk import score
from .blocklist import Blocklist

R, Y, G, B, X = "\033[91m", "\033[93m", "\033[92m", "\033[94m", "\033[0m"


def _h(s):
    return hashlib.sha256(s.encode()).hexdigest()[:10]


def run(speed=0.05, seconds=60, seed=None):
    rnd = random.Random(seed)
    bl = Blocklist()
    acct = defaultdict(set)      # device -> accounts tried (login velocity)
    cards = defaultdict(set)     # device -> cards tried (checkout velocity)
    recent = deque(maxlen=200)
    users = [f"user{i}" for i in range(300)]
    stats = defaultdict(int)
    end = time.time() + seconds
    phase_start = time.time()
    print(f"{B}Live CIAM & fraud monitor started. Ctrl+C to stop.{X}\n")
    try:
        while time.time() < end:
            t = time.time() - phase_start
            attack = "stuffing" if 15 < t % 45 < 25 else "cardtest" if 30 < t % 45 < 38 else None
            if attack == "stuffing":
                dev, u, kind = _h(f"bot{rnd.randint(0,2)}"), rnd.choice(users), "login"
                newdev, asn = True, True
            elif attack == "cardtest":
                dev, u, kind = _h("tester"), "guest", "checkout"
                newdev, asn = True, False
            else:
                u = rnd.choice(users); dev = _h("dev" + u)
                kind = "login" if rnd.random() < 0.7 else "checkout"
                newdev, asn = rnd.random() < 0.05, False
            stats["events"] += 1
            if bl.is_blocked(dev):
                stats["blocked"] += 1
                print(f"{R}BLOCKED  {kind:8} device={dev} (on blocklist){X}")
                time.sleep(speed); continue
            if kind == "login":
                acct[dev].add(u)
                vel = len(acct[dev]) >= 20
            else:
                cards[dev].add(_h(str(rnd.random())))
                vel = len(cards[dev]) >= 5
            d = score({"new_device": newdev, "risky_asn": asn, "velocity_hit": vel})
            stats[d["decision"]] += 1
            col = {"ALLOW": G, "CHALLENGE": Y, "BLOCK": R}[d["decision"]]
            print(f"{col}{d['decision']:9}{X} {kind:8} user={u:8} device={dev} score={d['score']:3} {','.join(d['reasons'])}")
            if vel and bl.add(dev, "VELOCITY", ttl_hours=24):
                rule = "CREDENTIAL STUFFING" if kind == "login" else "CARD TESTING"
                n = len(acct[dev]) if kind == "login" else len(cards[dev])
                print(f"\n{R}>>> ALERT: {rule} from device {dev} ({n} {'accounts' if kind=='login' else 'cards'}) -> blocklisted 24h{X}\n")
            time.sleep(speed)
    except KeyboardInterrupt:
        pass
    print(f"\n{B}Summary:{X} {dict(stats)}")
