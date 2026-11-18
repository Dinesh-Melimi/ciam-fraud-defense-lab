# Architecture

```
Customer -> CDN/WAF -> Bot management -> CIAM (login, MFA) ----\
                                   \-> Checkout -> Payment gw   |
                                                                v
          Telemetry (login_events, transactions, account_changes)
                                   |
                     Velocity detections (SQL / Python)
                                   |
             Risk score -> ALLOW / CHALLENGE (MFA, 3DS, CAPTCHA) / BLOCK
                                   |
            Blocklist (TTL + allowlist) -> pushed to WAF / fraud vendor API
```

Signals: device fingerprint, ASN, country, breached password, velocity.
Design principle: challenge before block, expire blocks, measure false positives.
