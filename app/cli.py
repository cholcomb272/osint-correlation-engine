"""Administrative CLI that keeps privileged tokens out of browsers."""

import argparse
import json

from sqlalchemy import func, select

from app.main import Event, NetworkMeasurement, SessionLocal
from app.worker import run_correlations, run_feeds, run_measurements


def main() -> None:
    parser = argparse.ArgumentParser(description="OSINT Correlation Engine administration")
    subcommands = parser.add_subparsers(dest="command", required=True)
    for name, default, maximum in (("collect", 30, 3650), ("collect-measurements", 7, 90), ("correlate", 30, 3650)):
        command = subcommands.add_parser(name)
        command.add_argument("--days", type=int, default=default, choices=range(1, maximum + 1), metavar=f"1..{maximum}")
    subcommands.add_parser("health")
    args = parser.parse_args()
    if args.command == "collect":
        result = run_feeds(args.days)
    elif args.command == "collect-measurements":
        result = run_measurements(args.days)
    elif args.command == "correlate":
        result = {"relationship_records": run_correlations(args.days)}
    else:
        with SessionLocal() as db:
            result = {
                "events": db.scalar(select(func.count()).select_from(Event)),
                "measurements": db.scalar(select(func.count()).select_from(NetworkMeasurement)),
            }
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
