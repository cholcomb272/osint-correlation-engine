"""Dedicated scheduled collection and correlation worker."""

import logging
import os
import time
from datetime import datetime, timezone

from apscheduler.schedulers.blocking import BlockingScheduler
from prometheus_client import Counter, Gauge, Histogram, start_http_server
from sqlalchemy import delete, select

from app.main import SessionLocal, collect, collect_network_measurements, measurement_poll_minutes, poll_minutes
from app.logging_config import configure_logging
from app.services.correlation import candidate_correlations, persist_candidates
from app.v2_models import CollectorCheckpoint, CollectorRun


logger = logging.getLogger("osint.worker")
COLLECTOR_RUNS = Counter("osint_collector_runs_total", "Collector runs", ("collector", "status"))
COLLECTOR_DURATION = Histogram("osint_collector_duration_seconds", "Collector duration", ("collector",))
SOURCE_FRESHNESS = Gauge("osint_source_freshness_timestamp", "Latest successful collection", ("collector",))
INGESTED = Counter("osint_ingested_records_total", "Inserted records", ("collector",))
DEDUPLICATED = Counter("osint_deduplicated_records_total", "Deduplicated records", ("collector",))
CORRELATION_DURATION = Histogram("osint_correlation_processing_duration_seconds", "Correlation processing duration")
CORRELATION_VOLUME = Gauge("osint_correlation_candidate_count", "Current correlation candidate count")
PROCESSING_BACKLOG = Gauge("osint_processing_backlog", "Queued in-process jobs")


def _record_summary(summary: dict, started: datetime, duration: float, prefix: str = "") -> None:
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        for name, values in summary.items():
            collector = f"{prefix}{name}"
            error = values.get("error") if isinstance(values, dict) else "invalid collector result"
            parsed = int(values.get("parsed", 0)) if isinstance(values, dict) else 0
            inserted = int(values.get("added", 0)) if isinstance(values, dict) else 0
            updated = int(values.get("updated", 0)) if isinstance(values, dict) else 0
            status = "failed" if error else "success"
            deduplicated = max(0, parsed - inserted)
            db.add(
                CollectorRun(
                    collector=collector,
                    started_at=started,
                    finished_at=now,
                    status=status,
                    fetched=parsed,
                    inserted=inserted,
                    updated=updated,
                    deduplicated=deduplicated,
                    error=str(error)[:2000] if error else None,
                    source_freshness_at=now if not error else None,
                    duration_seconds=duration,
                )
            )
            checkpoint = db.get(CollectorCheckpoint, collector)
            cursor = {"last_finished_at": now.isoformat(), "status": status}
            if checkpoint:
                checkpoint.cursor = cursor
                checkpoint.updated_at = now
            else:
                db.add(CollectorCheckpoint(collector=collector, cursor=cursor, updated_at=now))
            COLLECTOR_RUNS.labels(collector, status).inc()
            COLLECTOR_DURATION.labels(collector).observe(duration)
            INGESTED.labels(collector).inc(inserted)
            DEDUPLICATED.labels(collector).inc(deduplicated)
            if not error:
                SOURCE_FRESHNESS.labels(collector).set(now.timestamp())
        db.commit()


def run_feeds(days: int = 30) -> dict:
    started = datetime.now(timezone.utc)
    clock = time.perf_counter()
    try:
        result = collect(days)
    except Exception as exc:
        logger.exception("feed collection job failed")
        result = {"feed_job": {"error": str(exc)[:250]}}
    _record_summary(result, started, time.perf_counter() - clock, "feed:")
    return result


def run_measurements(days: int = 7) -> dict:
    started = datetime.now(timezone.utc)
    clock = time.perf_counter()
    try:
        result = collect_network_measurements(days)
    except Exception as exc:
        logger.exception("measurement collection job failed")
        result = {"measurement_job": {"error": str(exc)[:250]}}
    _record_summary(result, started, time.perf_counter() - clock, "measurement:")
    return result


def run_correlations(days: int = 30) -> int:
    clock = time.perf_counter()
    try:
        with SessionLocal() as db:
            candidates = candidate_correlations(db, days=days)
            count = persist_candidates(db, candidates)
            CORRELATION_VOLUME.set(len(candidates))
            return count
    except Exception:
        logger.exception("correlation rebuild failed")
        return 0
    finally:
        CORRELATION_DURATION.observe(time.perf_counter() - clock)


def apply_retention() -> dict[str, int]:
    """Prune operational metadata only; source events and evidence are retained."""
    from datetime import timedelta
    from app.v2_models import AuditLog, CorrelationRecord

    now = datetime.now(timezone.utc)
    audit_days = max(30, int(os.getenv("AUDIT_RETENTION_DAYS", "365")))
    run_days = max(30, int(os.getenv("COLLECTOR_RUN_RETENTION_DAYS", "180")))
    correlation_days = max(30, int(os.getenv("CORRELATION_RETENTION_DAYS", "180")))
    with SessionLocal() as db:
        audit = db.execute(delete(AuditLog).where(AuditLog.occurred_at < now - timedelta(days=audit_days))).rowcount or 0
        runs = db.execute(delete(CollectorRun).where(CollectorRun.started_at < now - timedelta(days=run_days))).rowcount or 0
        correlations = db.execute(delete(CorrelationRecord).where(CorrelationRecord.updated_at < now - timedelta(days=correlation_days))).rowcount or 0
        db.commit()
    return {"audit_logs": audit, "collector_runs": runs, "correlations": correlations}


def main() -> None:
    configure_logging()
    metrics_port = int(os.getenv("WORKER_METRICS_PORT", "9101"))
    start_http_server(metrics_port, addr="0.0.0.0")
    scheduler = BlockingScheduler(timezone="UTC")
    scheduler.add_job(run_feeds, "interval", minutes=poll_minutes(), id="feeds", max_instances=1, coalesce=True, next_run_time=datetime.now(timezone.utc))
    scheduler.add_job(run_measurements, "interval", minutes=measurement_poll_minutes(), id="measurements", max_instances=1, coalesce=True, next_run_time=datetime.now(timezone.utc))
    scheduler.add_job(run_correlations, "interval", minutes=max(5, poll_minutes()), id="correlations", max_instances=1, coalesce=True)
    if os.getenv("RETENTION_ENABLED", "false").casefold() == "true":
        scheduler.add_job(apply_retention, "cron", hour=3, minute=17, id="retention", max_instances=1, coalesce=True)
    logger.info("worker starting with feed interval=%sm measurement interval=%sm", poll_minutes(), measurement_poll_minutes())
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        logger.info("worker shutdown requested")
        scheduler.shutdown(wait=False)


if __name__ == "__main__":
    main()
