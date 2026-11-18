import argparse, json
from .generate import build
from .detect import run_all
from .blocklist import Blocklist
from .risk import score


def main():
    ap = argparse.ArgumentParser(description="CIAM & fraud defense lab")
    ap.add_argument("--db", default="fraudlab.db")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--live", action="store_true", help="stream traffic and detections in real time")
    ap.add_argument("--seconds", type=int, default=60)
    a = ap.parse_args()
    if a.live:
        from .live import run
        run(seconds=a.seconds)
        return
    con = build(a.db)
    findings = run_all(con)
    bl = Blocklist()
    blocked = bl.from_findings(findings)
    if a.json:
        print(json.dumps([f.__dict__ for f in findings], indent=2))
        return
    print(f"{len(findings)} findings, {blocked} devices pushed to blocklist (24h TTL)\n")
    for f in findings[:15]:
        print(f"[{f.severity:8}] {f.rule:20} {f.entity_type}:{f.entity}  {f.evidence}")
    print("\nExample risk decision:", score({"new_device": True, "risky_asn": True}))


if __name__ == "__main__":
    main()
