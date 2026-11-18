import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from datetime import datetime, timedelta
from fraudlab.generate import build
from fraudlab.detect import credential_stuffing, card_testing, ato_follow_through
from fraudlab.risk import score
from fraudlab.blocklist import Blocklist


def _con(tmp_path):
    return build(str(tmp_path / "t.db"))


def test_detects_credential_stuffing(tmp_path):
    assert len(credential_stuffing(_con(tmp_path))) >= 1


def test_detects_card_testing(tmp_path):
    f = card_testing(_con(tmp_path))
    assert len(f) == 1 and "cards" in f[0].evidence


def test_detects_ato(tmp_path):
    assert all(f.severity == "CRITICAL" for f in ato_follow_through(_con(tmp_path)))


def test_normal_user_not_flagged(tmp_path):
    devs = {f.entity for f in credential_stuffing(_con(tmp_path))}
    assert not any(d.startswith("user") for d in devs)


def test_risk_decisions():
    assert score({})["decision"] == "ALLOW"
    assert score({"new_device": True, "foreign_country": True})["decision"] == "CHALLENGE"
    assert score({"risky_asn": True, "breached_password": True})["decision"] == "BLOCK"


def test_blocklist_ttl_and_allowlist():
    bl = Blocklist(allowlist={"office"})
    now = datetime(2026, 1, 1)
    assert not bl.add("office", "x", now=now)
    bl.add("dev1", "CARD_TESTING", ttl_hours=1, now=now)
    assert bl.is_blocked("dev1", now=now)
    assert not bl.is_blocked("dev1", now=now + timedelta(hours=2))
