-- Credential stuffing: devices hitting many accounts
SELECT device_id, COUNT(*) attempts, COUNT(DISTINCT username) accounts,
       AVG(CASE WHEN result='SUCCESS' THEN 1.0 ELSE 0 END) success_rate
FROM login_events GROUP BY device_id HAVING accounts >= 20 ORDER BY accounts DESC;

-- Card testing: many cards per device, small amounts, high declines
SELECT device_id, COUNT(DISTINCT card_hash) cards, AVG(amount) avg_amount,
       SUM(CASE WHEN status='DECLINED' THEN 1 ELSE 0 END) declines
FROM transactions GROUP BY device_id HAVING cards >= 5 ORDER BY cards DESC;

-- Account takeover: new-device login followed by a profile change within 15 minutes
SELECT l.username, l.device_id, c.change_type, l.ts login_ts, c.ts change_ts
FROM login_events l JOIN account_changes c ON c.username = l.username
WHERE l.result='SUCCESS' AND l.known_device=0
  AND (julianday(c.ts) - julianday(l.ts)) * 1440 BETWEEN 0 AND 15;

-- BIN attack: spike of attempts within one BIN
SELECT bin, COUNT(*) attempts, COUNT(DISTINCT card_hash) cards
FROM transactions GROUP BY bin ORDER BY attempts DESC;
