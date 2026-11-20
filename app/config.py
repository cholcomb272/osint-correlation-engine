from functools import lru_cache

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, extra="ignore")

    app_env: str = "development"
    api_token: SecretStr | None = None
    audit_hash_salt: SecretStr | None = None
    cors_origins: str = ""
    public_rate_limit_per_minute: int = Field(120, ge=10, le=10000)
    max_request_bytes: int = Field(1_048_576, ge=1024, le=10_000_000)
    poll_minutes: int = Field(15, ge=1)
    measurement_poll_minutes: int = Field(60, ge=15)
    bgp_prefixes_per_asn: int = Field(4, ge=1, le=8)
    max_monitored_asns: int = Field(12, ge=1, le=50)

    @model_validator(mode="after")
    def validate_production(self):
        if self.app_env.casefold() == "production":
            token = self.api_token.get_secret_value() if self.api_token else ""
            audit_salt = self.audit_hash_salt.get_secret_value() if self.audit_hash_salt else ""
            if len(token) < 32:
                raise ValueError("API_TOKEN must be at least 32 characters in production")
            if len(audit_salt) < 32:
                raise ValueError("AUDIT_HASH_SALT must be at least 32 characters in production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
