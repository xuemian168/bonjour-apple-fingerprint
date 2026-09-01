from dataclasses import dataclass, field
from enum import StrEnum

from .sanitize import sanitize_text


def canonical_dns_name(value: str | bytes) -> str:
    """Return a case-insensitive absolute DNS name, preserving an empty value."""
    normalized = sanitize_text(value).strip().lower().rstrip(".")
    return f"{normalized[:511]}." if normalized else ""


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True, slots=True)
class ServiceObservation:
    service_type: str
    instance_name: str
    server: str
    port: int
    addresses: tuple[str, ...] = ()
    properties: dict[str, str] = field(default_factory=dict)
    interface: str | None = None
    port_resolved: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "service_type", canonical_dns_name(self.service_type)
        )
        object.__setattr__(self, "instance_name", sanitize_text(self.instance_name))
        object.__setattr__(self, "server", canonical_dns_name(self.server))
        object.__setattr__(self, "addresses", tuple(dict.fromkeys(self.addresses)))
        object.__setattr__(
            self,
            "properties",
            {sanitize_text(k).lower(): sanitize_text(v) for k, v in self.properties.items()},
        )

    @property
    def identity(self) -> tuple[str, str]:
        return self.service_type, self.instance_name


@dataclass(slots=True)
class DeviceRecord:
    server: str
    addresses: set[str] = field(default_factory=set)
    interfaces: set[str] = field(default_factory=set)
    services: dict[tuple[str, str], ServiceObservation] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Evidence:
    source: str
    value: str
    strength: Confidence


@dataclass(frozen=True, slots=True)
class ModelCandidate:
    identifier: str
    name: str
    source: str


@dataclass(frozen=True, slots=True)
class ClassificationResult:
    device: DeviceRecord
    category: str
    model: str
    confidence: Confidence
    evidence: tuple[Evidence, ...]
    candidates: tuple[ModelCandidate, ...] = ()
    missing: tuple[str, ...] = ()
    conflicts: tuple[str, ...] = ()
