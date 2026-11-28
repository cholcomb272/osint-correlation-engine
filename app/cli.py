"""Administrative CLI that keeps privileged tokens out of browsers."""

import argparse
import json
from pathlib import Path

from sqlalchemy import func, select

from app.main import Event, NetworkMeasurement, SessionLocal
from app.worker import run_correlations, run_feeds, run_intelligence_fusion, run_measurements


def main() -> None:
    parser = argparse.ArgumentParser(description="OSINT Correlation Engine administration")
    subcommands = parser.add_subparsers(dest="command", required=True)
    for name, default, maximum in (("collect", 30, 3650), ("collect-measurements", 7, 90), ("correlate", 30, 3650), ("fusion", 90, 3650)):
        command = subcommands.add_parser(name)
        command.add_argument("--days", type=int, default=default, choices=range(1, maximum + 1), metavar=f"1..{maximum}")
    subcommands.add_parser("health")
    benchmark = subcommands.add_parser(
        "benchmark", help="run deterministic correlation regression fixtures"
    )
    benchmark.add_argument("--fixture", type=Path)
    benchmark.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.command == "collect":
        result = run_feeds(args.days)
    elif args.command == "collect-measurements":
        result = run_measurements(args.days)
    elif args.command == "correlate":
        result = {"relationship_records": run_correlations(args.days)}
    elif args.command == "fusion":
        result = run_intelligence_fusion(args.days)
    elif args.command == "health":
        with SessionLocal() as db:
            result = {
                "events": db.scalar(select(func.count()).select_from(Event)),
                "measurements": db.scalar(select(func.count()).select_from(NetworkMeasurement)),
            }
    else:
        from app.services.benchmark import DEFAULT_FIXTURE, run_benchmark

        result = run_benchmark(args.fixture or DEFAULT_FIXTURE)
        if args.output:
            args.output.write_text(
                json.dumps(result, indent=2, default=str) + "\n", encoding="utf-8"
            )
    print(json.dumps(result, indent=2, default=str))
    if args.command == "benchmark" and not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
