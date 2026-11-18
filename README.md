# CIAM & Fraud Defense Lab

A hands-on lab for **customer identity security and payment fraud defense**: account takeover (ATO),
credential stuffing, card testing, risk-based authentication, and programmatic blocklists, mapped to
**PCI DSS v4.0**.

It generates realistic login and checkout telemetry with attacks hidden inside normal customer traffic,
then detects them with velocity analytics (SQL + Python) and makes explainable allow / challenge / block
decisions.

## What it detects
| Detection | Signal |
| --- | --- |
| Credential stuffing | One device hitting 20+ accounts with ~1% success, invalid usernames, residential-proxy ASN |
| Card testing | One device trying many cards, tiny amounts, high decline rate, single BIN |
| Account takeover | New-device login followed by email/phone/password change within 15 minutes |
| BIN attack | Spike of attempts inside one BIN range |

## Run it
```bash
PYTHONPATH=src python -m fraudlab            # findings + blocklist summary
PYTHONPATH=src python -m fraudlab --json     # machine-readable output
sqlite3 fraudlab.db < sql/investigations.sql # analyst SQL queries
python -m pytest -q
```

## Live demo
- **Web dashboard:** open `docs/index.html` in a browser, or view it on GitHub Pages at
  `https://dinesh-melimi.github.io/ciam-fraud-defense-lab/`. Click **Launch credential stuffing** or
  **Launch card testing** and watch detections, challenges, and blocklisting happen in real time.
- **Terminal:** `PYTHONPATH=src python -m fraudlab --live --seconds 90` streams events with color-coded
  ALLOW / CHALLENGE / BLOCK decisions and alerts.

## Interactive demo app
`docs/app/` is a working customer sign-in app plus a live Security Console (no server needed):
- **Sign in** (`docs/app/index.html`): risk-scored login, step-up MFA for new devices or breached passwords,
  lockout after 10 failures (PCI DSS 8.3.4), step-up before email change, 3-D Secure on add-card.
- **Security Console** (`docs/app/soc.html`): every decision streams in live; simulate credential stuffing
  or brute force and watch velocity detection blocklist the attacker.

Hosted: `https://dinesh-melimi.github.io/ciam-fraud-defense-lab/app/`

## Design choices
- **Device + behavior over IP**: attackers rotate residential IPs, so velocity keys on device fingerprint and ASN.
- **Challenge before block**: medium risk gets step-up MFA / 3-D Secure / CAPTCHA to protect real customers.
- **Blocks expire (TTL) with an allowlist**, so shared IPs and good users aren't stuck.
- **No card data stored**: only card hashes, in line with PCI DSS Requirement 3.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and [`docs/PCI_DSS_mapping.md`](docs/PCI_DSS_mapping.md).

## Roadmap
- Impossible-travel detection and session-hijack signals (token reuse after rotation)
- Splunk SPL / Sentinel KQL versions of each detection
- Feedback loop from chargebacks to tune thresholds and measure false-positive rate

## License
MIT
