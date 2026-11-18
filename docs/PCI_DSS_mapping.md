# PCI DSS v4.0 Mapping

| Control in this lab | PCI DSS v4.0 requirement |
| --- | --- |
| Risk-based step-up (CHALLENGE) for new devices | 8.4 / 8.5 – MFA and MFA systems resistant to misuse |
| Lockout / velocity limits on failed logins | 8.3.4 – lock after no more than 10 invalid attempts |
| Role-based access to fraud tooling and blocklists | 7.2 – access by job function and least privilege |
| Login, change and transaction telemetry with user/device/IP/result | 10.2 – audit logs capture user activity |
| Automated review of detections | 10.4.1.1 – automated log review |
| Card data stored only as hashes (`card_hash`), never PAN/CVV | 3.3 / 3.4 – no SAD after auth, PAN rendered unreadable |
| Checkout bot/card-testing controls | 6.4.3 / 11.6.1 – protect payment pages from tampering |
