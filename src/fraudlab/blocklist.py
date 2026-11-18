"""Blocklist with TTL and allowlist so blocks expire and good users aren't stuck."""
from datetime import datetime, timedelta


class Blocklist:
    def __init__(self, allowlist=None):
        self.entries = {}
        self.allow = set(allowlist or [])

    def add(self, entity, reason, ttl_hours=24, now=None):
        if entity in self.allow:
            return False
        now = now or datetime.utcnow()
        self.entries[entity] = {"reason": reason, "expires": now + timedelta(hours=ttl_hours)}
        return True

    def is_blocked(self, entity, now=None):
        now = now or datetime.utcnow()
        e = self.entries.get(entity)
        if not e:
            return False
        if now >= e["expires"]:
            del self.entries[entity]
            return False
        return True

    def from_findings(self, findings, ttl_hours=24):
        return sum(self.add(f.entity, f.rule, ttl_hours) for f in findings if f.entity_type == "device")
