"""Dedicated scheduled collection and correlation worker."""

import logging
import os
import time
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.blocking import BlockingScheduler
from prometheus_client import Counter, Gauge, Histogram, start_http_server
from sqlalchemy import delete, func, select

from app.main import Event, FEED_SOURCES, SessionLocal, collect, collect_network_measurements, measurement_poll_minutes, poll_minutes
from app.logging_config import configure_logging
from app.services.correlation import candidate_correlations, persist_candidates
from app.services.fusion import run_fusion
from app.v2_models import CollectorCheckpoint, CollectorRun, SourceCoverageSnapshot


logger = logging.getLogger("osint.worker")
COLLECTOR_RUNS = Counter("osint_collector_runs_total", "Collector runs", ("collector", "status"))
COLLECTOR_DURATION = Histogram("osint_collector_duration_seconds", "Collector duration", ("collector",))
SOURCE_FRESHNESS = Gauge("osint_source_freshness_timestamp", "Latest successful collection", ("collector",))
INGESTED = Counter("osint_ingested_records_total", "Inserted records", ("collector",))
DEDUPLICATED = Counter("osint_deduplicated_records_total", "Deduplicated records", ("collector",))
CORRELATION_DURATION = Histogram("osint_correlation_processing_duration_seconds", "Correlation processing duration")
CORRELATION_VOLUME = Gauge("osint_correlation_candidate_count", "Current correlation candidate count")
PROCESSING_BACKLOG = Gauge("osint_processing_backlog", "Queued in-process jobs")
FUSION_DURATION = Histogram("osint_fusion_processing_duration_seconds", "Knowledge-graph fusion processing duration")
FUSION_RELATIONSHIPS = Gauge("osint_fusion_relationship_count", "Relationships evaluated in the latest fusion run")
FUSION_CLUSTERS = Gauge("osint_fusion_cluster_count", "Clusters found in the latest fusion run")
INVESTIGATION_CANDIDATES = Gauge("osint_investigation_candidate_count", "Investigation candidates in the latest fusion run")


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
            deduplicated = max(0, parsed - inserted - updated)
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
            if prefix == "feed:" and name in FEED_SOURCES:
                definition = FEED_SOURCES[name]
                latest_event = db.scalar(
                    select(func.max(Event.publisher_reported_at)).where(Event.source == name)
                )
                freshness = (
                    max(0.0, (now - latest_event).total_seconds())
                    if latest_event
                    else None
                )
                gaps = []
                if error:
                    gaps.append("latest collection failed")
                if not parsed:
                    gaps.append("no eligible records were visible in the requested window")
                if definition.languages == ["en"]:
                    gaps.append("source coverage is English-only")
                if definition.geographic_scope not in (["global"], ["global_technology"]):
                    gaps.append(
                        "publisher scope is limited to "
                        + ", ".join(definition.geographic_scope)
                    )
                expected_seconds = (
                    definition.expected_cadence_minutes * 60
                    if definition.expected_cadence_minutes
                    else None
                )
                coverage_status = (
                    "failed"
                    if error
                    else "no_recent_items"
                    if not parsed
                    else "stale"
                    if freshness is not None
                    and expected_seconds is not None
                    and freshness > expected_seconds * 4
                    else "healthy"
                )
                db.add(
                    SourceCoverageSnapshot(
                        source_id=name,
                        captured_at=now,
                        domains=definition.domains,
                        geographic_scope=definition.geographic_scope,
                        languages=definition.languages,
                        observed_items=parsed,
                        expected_cadence_minutes=definition.expected_cadence_minutes,
                        freshness_seconds=freshness,
                        completeness=None,
                        status=coverage_status,
                        gaps=gaps,
                        notes=[
                            "Completeness is not estimated without a trustworthy source denominator.",
                            "A healthy collector does not imply comprehensive event coverage.",
                        ],
                    )
                )
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


def run_intelligence_fusion(days: int = 90) -> dict:
    clock = time.perf_counter()
    PROCESSING_BACKLOG.inc()
    try:
        with SessionLocal() as db:
            result = run_fusion(db, days=days)
            FUSION_RELATIONSHIPS.set(result["relationships"]["relationships_evaluated"])
            FUSION_CLUSTERS.set(result["clusters"]["clusters"])
            INVESTIGATION_CANDIDATES.set(result["clusters"]["investigation_candidates"])
            return result
    except Exception as exc:
        logger.exception("intelligence fusion rebuild failed")
        return {"error": str(exc)[:250]}
    finally:
        PROCESSING_BACKLOG.dec()
        FUSION_DURATION.observe(time.perf_counter() - clock)


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
    scheduler.add_job(
        run_intelligence_fusion,
        "interval",
        minutes=max(15, poll_minutes()),
        id="intelligence_fusion",
        max_instances=1,
        coalesce=True,
        next_run_time=datetime.now(timezone.utc) + timedelta(minutes=2),
    )
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
