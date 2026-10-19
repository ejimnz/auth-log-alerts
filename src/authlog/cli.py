import argparse
from datetime import date

from authlog.parser import parse_lines


def main() -> None:
    ap = argparse.ArgumentParser(prog="authlog", description="Read SSH logins from an auth log.")
    ap.add_argument("logfile", help="path to an auth.log file")
    ap.add_argument("--year", type=int, default=date.today().year,
                    help="year of the log (syslog lines don't include one)")
    args = ap.parse_args()

    with open(args.logfile, encoding="utf-8", errors="replace") as f:
        events = list(parse_lines(f, args.year))

    for e in events:
        result = "OK  " if e.success else "FAIL"
        note = " (invalid user)" if e.invalid_user else ""
        print(f"{e.timestamp:%Y-%m-%d %H:%M:%S}  {result}  {e.user:<10} {e.ip:<15} {e.method}{note}")

    failed = sum(not e.success for e in events)
    print(f"\n{len(events)} login attempts, {failed} failed")


if __name__ == "__main__":
    main()
