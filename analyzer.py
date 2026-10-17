import argparse

from parsers.auth_parser import parse_auth
from detectors.bruteforce import detect_bruteforce, detect_success_after_failures


def main():
    ap = argparse.ArgumentParser(description="Detect attacks in Linux auth logs")
    ap.add_argument("--log", required=True, help="path to auth.log")
    ap.add_argument("--threshold", type=int, default=5, help="failures needed to alert")
    ap.add_argument("--window", type=int, default=120, help="window in seconds")
    ap.add_argument("--year", type=int, default=2026, help="year for old-style timestamps")
    args = ap.parse_args()

    events = parse_auth(args.log, year=args.year)
    print(f"{len(events)} login events parsed\n")

    alerts = detect_bruteforce(events, args.threshold, args.window)
    alerts += detect_success_after_failures(events)

    if not alerts:
        print("No alerts.")
    for a in alerts:
        print(f"[{a['severity'].upper()}] {a['type']} ({a['technique']})")
        print(f"   ip={a['ip']}  count={a['count']}  users={a['users']}")
        print(f"   {a['first_seen']}  ->  {a['last_seen']}\n")


if __name__ == "__main__":
    main()
