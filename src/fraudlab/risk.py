"""Simple explainable risk scoring: allow / challenge / block."""

WEIGHTS = {"new_device": 25, "risky_asn": 30, "foreign_country": 15,
           "breached_password": 40, "velocity_hit": 35}


def score(signals):
    s = sum(WEIGHTS[k] for k, v in signals.items() if v and k in WEIGHTS)
    s = min(s, 100)
    if s >= 70:
        decision = "BLOCK"
    elif s >= 35:
        decision = "CHALLENGE"  # step-up MFA / 3-D Secure / CAPTCHA
    else:
        decision = "ALLOW"
    reasons = [k for k, v in signals.items() if v]
    return {"score": s, "decision": decision, "reasons": reasons}
