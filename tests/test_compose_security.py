from pathlib import Path

import pytest
from pydantic import ValidationError

from app.config import Settings


def test_compose_requires_four_independent_secret_inputs() -> None:
    compose = Path("docker-compose.yml").read_text()

    assert "${POSTGRES_PASSWORD:?Set POSTGRES_PASSWORD in .env}" in compose
    assert "${APP_DB_PASSWORD:?Set APP_DB_PASSWORD in .env}" in compose
    assert "${API_TOKEN:?Set API_TOKEN in .env}" in compose
    assert "${AUDIT_HASH_SALT:?Set AUDIT_HASH_SALT in .env}" in compose
    assert "${APP_DB_PASSWORD:-${POSTGRES_PASSWORD}}" not in compose
    assert "${AUDIT_HASH_SALT:-${API_TOKEN}}" not in compose


def test_production_requires_audit_hash_salt() -> None:
    with pytest.raises(ValidationError, match="AUDIT_HASH_SALT"):
        Settings(app_env="production", api_token="a" * 32)


def test_production_accepts_explicit_api_and_audit_secrets() -> None:
    settings = Settings(
        app_env="production",
        api_token="a" * 32,
        audit_hash_salt="b" * 32,
    )

    assert settings.api_token is not None
    assert settings.audit_hash_salt is not None
