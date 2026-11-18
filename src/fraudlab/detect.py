"""Velocity-based detections for credential stuffing, card testing and ATO."""
from dataclasses import dataclass


@dataclass
class Finding:
    rule: str
    entity_type: str
    entity: str
    severity: str
    evidence: str


def credential_stuffing(con, min_accounts=20):
    q = """SELECT device_id, COUNT(*) attempts, COUNT(DISTINCT username) accounts,
                  AVG(CASE WHEN result='SUCCESS' THEN 1.0 ELSE 0 END) success_rate
           FROM login_events GROUP BY device_id HAVING accounts >= ? ORDER BY accounts DESC"""
    return [Finding("CRED_STUFFING", "device", d, "HIGH",
                    f"{a} attempts, {n} accounts, success {r:.1%}")
            for d, a, n, r in con.execute(q, (min_accounts,))]


def card_testing(con, min_cards=5):
    q = """SELECT device_id, COUNT(DISTINCT card_hash) cards,
                  SUM(CASE WHEN status='DECLINED' THEN 1 ELSE 0 END)*1.0/COUNT(*) decline_rate,
                  AVG(amount) avg_amt
           FROM transactions GROUP BY device_id HAVING cards >= ? ORDER BY cards DESC"""
    return [Finding("CARD_TESTING", "device", d, "HIGH",
                    f"{c} cards, decline {dr:.0%}, avg ${a:.2f}")
            for d, c, dr, a in con.execute(q, (min_cards,))]


def ato_follow_through(con, window_min=15):
    q = """SELECT l.username, l.device_id, c.change_type, l.ts
           FROM login_events l JOIN account_changes c ON c.username = l.username
           WHERE l.result='SUCCESS' AND l.known_device=0
             AND (julianday(c.ts) - julianday(l.ts)) * 1440 BETWEEN 0 AND ?"""
    return [Finding("ATO_ACCOUNT_CHANGE", "account", u, "CRITICAL",
                    f"new-device login then {ch} change ({ts})")
            for u, d, ch, ts in con.execute(q, (window_min,))]


def run_all(con):
    return credential_stuffing(con) + card_testing(con) + ato_follow_through(con)
