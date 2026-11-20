"""Bounded, incident-aware passive network measurement targets.

Target discovery expands configured seed prefixes with prefixes RIPE RIS reports
as originated by an incident ASN.  Discovery is deterministic and capped so a
large provider cannot create an unbounded collection workload.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from ipaddress import ip_network
from typing import Any, Iterable


ASN_PATTERN = re.compile(r"^AS([1-9][0-9]{0,9})$", re.IGNORECASE)


@dataclass(frozen=True)
class AsnScope:
    asn: str
    provider: str | None
    seed_prefixes: tuple[str, ...]
    selection_reason: str
    incident_aware: bool = False


@dataclass(frozen=True)
class NetworkTarget:
    asn: str
    provider: str | None
    prefix: str
    selection_reason: str
    scope_reason: str
    discovery_source: str
    incident_aware: bool


def normalize_asn(value: str | None) -> str | None:
    if not value:
        return None
    match = ASN_PATTERN.fullmatch(value.strip())
    return f"AS{match.group(1)}" if match else None


def _valid_public_prefix(value: str) -> str | None:
    try:
        network = ip_network(value.strip(), strict=False)
    except (AttributeError, ValueError):
        return None
    if not network.is_global:
        return None
    return str(network)


def build_asn_scopes(
    events: Iterable[Any],
    provider_metadata: dict[str, dict[str, str]],
    *,
    maximum_asns: int,
) -> list[AsnScope]:
    """Merge configured scopes with recently observed incident ASNs."""
    scopes: dict[str, dict[str, Any]] = {}
    for provider, metadata in provider_metadata.items():
        asn = normalize_asn(metadata.get("asn"))
        prefix = _valid_public_prefix(metadata.get("prefix", ""))
        if not asn:
            continue
        entry = scopes.setdefault(
            asn,
            {
                "provider": provider,
                "seed_prefixes": [],
                "selection_reason": "configured_provider_seed",
                "incident_aware": False,
            },
        )
        if prefix and prefix not in entry["seed_prefixes"]:
            entry["seed_prefixes"].append(prefix)

    for event in events:
        asn = normalize_asn(getattr(event, "asn", None))
        if not asn:
            continue
        provider = getattr(event, "provider", None)
        entry = scopes.setdefault(
            asn,
            {
                "provider": provider,
                "seed_prefixes": [],
                "selection_reason": "recent_incident_asn",
                "incident_aware": True,
            },
        )
        entry["incident_aware"] = True
        if entry["selection_reason"] == "configured_provider_seed":
            entry["selection_reason"] = (
                "configured_provider_seed+recent_incident_asn"
            )
        if not entry["provider"] and provider:
            entry["provider"] = provider

    ordered = sorted(
        scopes.items(),
        key=lambda item: (
            not item[1]["selection_reason"].startswith("configured_provider_seed"),
            item[0],
        ),
    )[:maximum_asns]
    return [
        AsnScope(
            asn=asn,
            provider=metadata["provider"],
            seed_prefixes=tuple(metadata["seed_prefixes"]),
            selection_reason=metadata["selection_reason"],
            incident_aware=metadata["incident_aware"],
        )
        for asn, metadata in ordered
    ]


def select_announced_prefixes(
    payload: dict,
    *,
    seed_prefixes: Iterable[str] = (),
    limit: int = 4,
) -> list[tuple[str, str]]:
    """Select stable IPv4/IPv6 targets from RIPE announced-prefix data."""
    if limit < 1:
        return []
    seeds = [prefix for value in seed_prefixes if (prefix := _valid_public_prefix(value))]
    discovered: set[str] = set()
    for record in payload.get("data", {}).get("prefixes", []):
        raw = record.get("prefix") if isinstance(record, dict) else record
        prefix = _valid_public_prefix(str(raw or ""))
        if prefix:
            discovered.add(prefix)

    candidates = sorted(
        discovered,
        key=lambda value: (
            ip_network(value).version,
            ip_network(value).prefixlen,
            int(ip_network(value).network_address),
        ),
    )
    selected: list[tuple[str, str]] = []
    for prefix in seeds:
        if prefix not in {item[0] for item in selected}:
            selected.append((prefix, "configured_provider_seed"))
            if len(selected) == limit:
                return selected

    # Prefer address-family diversity before filling the remaining bounded set.
    selected_families = {ip_network(prefix).version for prefix, _ in selected}
    for family in (4, 6):
        if family in selected_families:
            continue
        candidate = next(
            (value for value in candidates if ip_network(value).version == family),
            None,
        )
        if candidate:
            selected.append((candidate, "ripe_announced_prefix"))
            selected_families.add(family)
            if len(selected) == limit:
                return selected

    for prefix in candidates:
        if prefix not in {item[0] for item in selected}:
            selected.append((prefix, "ripe_announced_prefix"))
            if len(selected) == limit:
                break
    return selected


def targets_for_scope(
    scope: AsnScope,
    payload: dict,
    *,
    prefixes_per_asn: int,
) -> list[NetworkTarget]:
    return [
        NetworkTarget(
            asn=scope.asn,
            provider=scope.provider,
            prefix=prefix,
            selection_reason=reason,
            scope_reason=scope.selection_reason,
            discovery_source="ripe_stat_announced_prefixes",
            incident_aware=(
                scope.incident_aware
                or "recent_incident_asn" in scope.selection_reason
            ),
        )
        for prefix, reason in select_announced_prefixes(
            payload,
            seed_prefixes=scope.seed_prefixes,
            limit=prefixes_per_asn,
        )
    ]
