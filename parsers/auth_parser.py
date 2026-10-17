import re
from datetime import datetime

TS = r"(?P<ts>\d{4}-\d{2}-\d{2}T[\d:.]+[+-]\d{2}:\d{2}|\w{3}\s+\d+\s[\d:]{8})"

FAILED = re.compile(
    TS + r".*sshd.*Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
)
ACCEPTED = re.compile(
    TS + r".*sshd.*Accepted \w+ for (?P<user>\S+) from (?P<ip>[\d.]+)"
)


def _parse_ts(raw, year):
    if "T" in raw:
        return datetime.fromisoformat(raw).replace(tzinfo=None)
    return datetime.strptime(f"{year} {raw}", "%Y %b %d %H:%M:%S")


def parse_auth(path, year=2026):
    events = []
    with open(path, errors="ignore") as f:
        for line in f:
            for status, rx in (("failed", FAILED), ("success", ACCEPTED)):
                m = rx.search(line)
                if m:
                    events.append({
                        "ts": _parse_ts(m["ts"], year),
                        "user": m["user"],
                        "ip": m["ip"],
                        "status": status,
                    })
                    break
    return events
