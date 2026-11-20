from collections import defaultdict
from datetime import datetime, timedelta, timezone
from statistics import median

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.main import Event, as_utc


def _mad(values: list[float], center: float) -> float:
    return median([abs(value - center) for value in values]) if values else 0.0


def historical_trends(db: Session, *, days: int = 90, dimension: str = "provider", cutoff: datetime | None = None) -> list[dict]:
    if dimension not in {"provider", "region", "category"}:
        raise ValueError("unsupported baseline dimension")
    end = as_utc(cutoff or datetime.now(timezone.utc))
    start = end - timedelta(days=days)
    events = db.scalars(
        select(Event).where(
            Event.observed_at >= start,
            Event.observed_at <= end,
            Event.category != "scheduled_maintenance",
        )
    ).all()
    grouped: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    coverage_days: dict[str, set[str]] = defaultdict(set)
    seasonal_counts: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))
    for event in events:
        value = getattr(event, dimension) or "unknown"
        day = as_utc(event.observed_at).date().isoformat()
        grouped[value][day] += 1
        coverage_days[value].add(day)
        seasonal_counts[value][as_utc(event.observed_at).weekday() * 24 + as_utc(event.observed_at).hour] += 1

    output = []
    for value, counts in grouped.items():
        series = []
        for offset in range(days):
            day = (start.date() + timedelta(days=offset)).isoformat()
            series.append(float(counts.get(day, 0)))
        baseline = series[:-7] or series
        current = sum(series[-7:]) / max(1, min(7, len(series)))
        center = median(baseline) if baseline else 0.0
        mad = _mad(baseline, center)
        robust_z = round(0.6745 * (current - center) / mad, 3) if mad else None
        recent_median = median(series[-7:]) if series else 0.0
        prior_median = median(series[-14:-7]) if len(series) >= 14 else center
        change_point = bool(mad and abs(recent_median - prior_median) > 3 * mad)
        weeks = max(1.0, days / 7)
        current_slot = end.weekday() * 24 + end.hour
        output.append(
            {
                "dimension": dimension,
                "value": value,
                "period_days": days,
                "daily_median": center,
                "median_absolute_deviation": mad,
                "recent_daily_average": round(current, 3),
                "robust_anomaly_score": robust_z,
                "change_point_candidate": change_point,
                "seasonal_hour_of_week": {
                    "slot": current_slot,
                    "expected_events": round(seasonal_counts[value].get(current_slot, 0) / weeks, 3),
                    "sample_weeks": round(weeks, 2),
                },
                "coverage_ratio": round(len(coverage_days[value]) / max(1, days), 3),
                "notes": [
                    "Score uses median absolute deviation and is not a probability.",
                    "Zeros may reflect either no events or missing source coverage.",
                ],
                "series": series,
            }
        )
    return sorted(output, key=lambda item: abs(item["robust_anomaly_score"] or 0), reverse=True)
