from types import SimpleNamespace

from app.services.network_targets import (
    AsnScope,
    build_asn_scopes,
    select_announced_prefixes,
    targets_for_scope,
)


def test_scopes_merge_configured_and_recent_incident_asns_with_a_cap():
    providers = {
        "example": {"asn": "AS64500", "prefix": "1.1.1.0/24"},
    }
    events = [
        SimpleNamespace(asn="AS64501", provider="incident-provider"),
        SimpleNamespace(asn="not-an-asn", provider="ignored"),
    ]
    scopes = build_asn_scopes(events, providers, maximum_asns=2)
    assert [scope.asn for scope in scopes] == ["AS64500", "AS64501"]
    assert scopes[0].selection_reason == "configured_provider_seed"
    assert scopes[1].selection_reason == "recent_incident_asn"


def test_prefix_selection_is_bounded_public_and_address_family_diverse():
    payload = {
        "data": {
            "prefixes": [
                {"prefix": "203.0.113.0/24"},
                {"prefix": "8.8.8.0/24"},
                {"prefix": "2001:4860::/32"},
                {"prefix": "10.0.0.0/8"},
                {"prefix": "invalid"},
            ]
        }
    }
    selected = select_announced_prefixes(
        payload, seed_prefixes=["1.1.1.0/24"], limit=3
    )
    assert selected[0] == ("1.1.1.0/24", "configured_provider_seed")
    assert any(":" in prefix for prefix, _ in selected)
    assert len(selected) == 3
    assert all(prefix not in {"10.0.0.0/8", "203.0.113.0/24"} for prefix, _ in selected)


def test_targets_retain_incident_scope_provenance():
    scope = AsnScope(
        asn="AS15169",
        provider="google",
        seed_prefixes=("8.8.8.0/24",),
        selection_reason="recent_incident_asn",
    )
    targets = targets_for_scope(
        scope,
        {"data": {"prefixes": [{"prefix": "2001:4860::/32"}]}},
        prefixes_per_asn=2,
    )
    assert {target.scope_reason for target in targets} == {"recent_incident_asn"}
    assert {target.discovery_source for target in targets} == {
        "ripe_stat_announced_prefixes"
    }
    assert all(target.incident_aware for target in targets)


def test_configured_scope_is_also_marked_incident_aware_when_observed():
    scopes = build_asn_scopes(
        [SimpleNamespace(asn="AS64500", provider="example")],
        {"example": {"asn": "AS64500", "prefix": "1.1.1.0/24"}},
        maximum_asns=1,
    )
    assert scopes[0].incident_aware is True
    assert scopes[0].selection_reason == (
        "configured_provider_seed+recent_incident_asn"
    )
