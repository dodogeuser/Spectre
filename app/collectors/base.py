"""Trusted plugin contract: immutable seed, controlled client, no database handle."""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.services.http_client import ControlledHttpClient


@dataclass(frozen=True)
class CollectorTarget:
    id: int
    type: str
    normalized_value: str
    scope_status: str


@dataclass(frozen=True)
class CollectorContext:
    http: ControlledHttpClient


class EvidenceItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_type: str = Field(min_length=1, max_length=50)
    source_ref: str = Field(min_length=1, max_length=2048)
    raw_json: dict
    parsed_json: dict


class CollectorResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    evidence: list[EvidenceItem] = Field(default_factory=list, max_length=100)
    warnings: list[str] = Field(default_factory=list, max_length=20)
    status: Literal["completed", "failed"] = "completed"
    error_code: Literal["provider_http_error", "provider_unavailable", "malformed_response", "dns_error", "bootstrap_unavailable", "timeout", "network_policy", "collector_error"] | None = None


class Collector(ABC):
    name: str
    version: str
    supported_types: frozenset[str]
    passive: bool = True

    @abstractmethod
    async def collect(self, target: CollectorTarget, context: CollectorContext) -> CollectorResult:
        ...
