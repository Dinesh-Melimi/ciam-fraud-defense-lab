DROP TABLE IF EXISTS login_events;
DROP TABLE IF EXISTS transactions;
DROP TABLE IF EXISTS account_changes;
CREATE TABLE login_events (ts TEXT, username TEXT, ip TEXT, asn INTEGER, device_id TEXT,
                           country TEXT, result TEXT, known_device INTEGER);
CREATE TABLE transactions (ts TEXT, username TEXT, device_id TEXT, card_hash TEXT, bin TEXT,
                           amount REAL, status TEXT, channel TEXT);
CREATE TABLE account_changes (ts TEXT, username TEXT, change_type TEXT);
