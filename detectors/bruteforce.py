from collections import defaultdict
from datetime import timedelta


def detect_bruteforce(events, threshold=5, window_seconds=120):
    """Flag IPs with `threshold` or more failed logins inside one time window."""
    window = timedelta(seconds=window_seconds)

    # 1. Group failed logins by source IP
    failures = defaultdict(list)
    for e in events:
        if e["status"] == "failed":
            failures[e["ip"]].append(e)

    alerts = []
    for ip, evs in failures.items():
        evs.sort(key=lambda e: e["ts"])

        # 2. Slide a window over the sorted events, remember the densest burst
        start = 0
        best_count, best_start, best_end = 0, 0, 0
        for end in range(len(evs)):
            while evs[end]["ts"] - evs[start]["ts"] > window:
                start += 1
            count = end - start + 1
            if count > best_count:
                best_count, best_start, best_end = count, start, end

        # 3. Alert only if the densest burst reaches the threshold
        if best_count >= threshold:
            burst = evs[best_start:best_end + 1]
            alerts.append({
                "type": "ssh_bruteforce",
                "ip": ip,
                "count": best_count,
                "first_seen": burst[0]["ts"],
                "last_seen": burst[-1]["ts"],
                "users": sorted({e["user"] for e in burst}),
                "severity": "high" if best_count >= threshold * 4 else "medium",
                "technique": "T1110",
            })
    return alerts


def detect_success_after_failures(events, min_failures=3, window_seconds=300):
    """Flag a successful login preceded by several failures from the same IP."""
    window = timedelta(seconds=window_seconds)
    ordered = sorted(events, key=lambda e: e["ts"])

    alerts = []
    for i, e in enumerate(ordered):
        if e["status"] != "success":
            continue
        # Look back at earlier events from the same IP and the same user
        recent_fails = [
            p for p in ordered[:i]
            if p["status"] == "failed"
            and p["ip"] == e["ip"]
            and p["user"] == e["user"]
            and e["ts"] - p["ts"] <= window
        ]
        if len(recent_fails) >= min_failures:
            alerts.append({
                "type": "success_after_failures",
                "ip": e["ip"],
                "count": len(recent_fails),
                "first_seen": recent_fails[0]["ts"],
                "last_seen": e["ts"],
                "users": [e["user"]],
                "severity": "high",
                "technique": "T1110",
            })
    return alerts
