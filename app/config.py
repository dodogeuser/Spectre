"""Validated environment configuration for the local application."""

from functools import lru_cache
from typing import Literal
from pathlib import Path

from pydantic import Field, SecretStr, model_validator, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SPECTRE_", env_file=".env", env_file_encoding="utf-8", extra="forbid"
    )

    app_name: str = Field(default="SPECTRE", min_length=1, max_length=100)
    environment: Literal["local", "development", "production"] = "local"
    bind_host: str = Field(default="127.0.0.1", min_length=1)
    bind_port: int = Field(default=8000, ge=1, le=65535)
    secure_cookies: bool = False
    output_dir: Path = Path("output")
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    mysql_host: str = Field(default="127.0.0.1", min_length=1)
    mysql_port: int = Field(default=3306, ge=1, le=65535)
    mysql_database: str = Field(default="spectre", min_length=1)
    mysql_user: str = Field(default="spectre", min_length=1)
    mysql_password: SecretStr = SecretStr("")
    session_hours: int = Field(default=8, ge=1, le=24)
    collector_timeout_seconds: float = Field(default=10, ge=0.1, le=60)
    collector_retries: int = Field(default=1, ge=0, le=2)
    collector_max_response_bytes: int = Field(default=1048576, ge=1024, le=5242880)
    collector_host_interval_seconds: float = Field(default=1, ge=0.1, le=60)
    collector_max_redirects: int = Field(default=3, ge=0, le=5)
    dns_enabled: bool = True
    rdap_enabled: bool = True
    ct_enabled: bool = True
    reverse_dns_enabled: bool = True
    ip_rdap_enabled: bool = True
    ip_asn_enabled: bool = True
    web_metadata_enabled: bool = True
    ai_enabled: bool = False
    active_assessment_enabled: bool = False
    ai_model: str = Field(default="", max_length=100, pattern=r"^[a-zA-Z0-9_.:/-]*$")
    ai_timeout_seconds: float = Field(default=30, ge=1, le=60)

    @model_validator(mode="after")
    def production_requirements(self):
        if self.environment == "production":
            if not self.mysql_password.get_secret_value() or self.mysql_password.get_secret_value() == "CHANGE_ME":
                raise ValueError("Production requires a configured database password")
            if self.mysql_user.lower() == "root":
                raise ValueError("Production requires a dedicated database account")
            if not self.secure_cookies or self.log_level == "DEBUG":
                raise ValueError("Production requires secure cookies and non-DEBUG logging")
        return self


@lru_cache
def get_settings() -> Settings:
    try:return Settings()
    except ValidationError:
        raise RuntimeError("Invalid SPECTRE configuration; check .env.example or run python -m app.doctor (values withheld)") from None
