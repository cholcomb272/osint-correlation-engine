"""Load explicitly synthetic, idempotent demonstration records."""

import json
from pathlib import Path

from app.main import EventIn, SessionLocal, insert_event


def main() -> None:
    path = Path(__file__).parent / "data" / "demo_scenarios.json"
    payload = json.loads(path.read_text())
    if payload.get("synthetic") is not True:
        raise RuntimeError("demo fixture must be explicitly marked synthetic")
    created = 0
    existing = 0
    with SessionLocal() as db:
        for raw in payload["events"]:
            event = EventIn(**raw, raw_metadata={"synthetic": True, "fixture": path.name})
            _, was_created, _ = insert_event(db, event)
            created += int(was_created)
            existing += int(not was_created)
    print(json.dumps({"notice": payload["notice"], "created": created, "existing": existing}, indent=2))


if __name__ == "__main__":
    main()
