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
class ObservationProvenance:
    interface: str | None
    addresses: tuple[str, ...]
    port: int
    port_resolved: bool = True

    def __post_init__(self) -> None:
        interface = sanitize_text(self.interface).strip() if self.interface else None
        object.__setattr__(self, "interface", interface or None)
        object.__setattr__(
            self,
            "addresses",
            tuple(dict.fromkeys(sanitize_text(item) for item in self.addresses)),
        )


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
    provenance: tuple[ObservationProvenance, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "service_type", canonical_dns_name(self.service_type)
        )
        object.__setattr__(self, "instance_name", sanitize_text(self.instance_name))
        object.__setattr__(self, "server", canonical_dns_name(self.server))
        addresses = tuple(
            dict.fromkeys(sanitize_text(item) for item in self.addresses)
        )
        object.__setattr__(self, "addresses", addresses)
        object.__setattr__(
            self,
            "properties",
            {sanitize_text(k).lower(): sanitize_text(v) for k, v in self.properties.items()},
        )
        provenance = self.provenance or (
            ObservationProvenance(
                self.interface,
                addresses,
                self.port,
                self.port_resolved,
            ),
        )
        provenance = tuple(
            sorted(
                set(provenance),
                key=lambda item: (
                    item.interface or "",
                    item.addresses,
                    item.port,
                    item.port_resolved,
                ),
            )
        )
        object.__setattr__(self, "provenance", provenance)
        interfaces = tuple(
            sorted({item.interface for item in provenance if item.interface})
        )
        object.__setattr__(
            self,
            "interface",
            interfaces[0] if len(interfaces) == 1 else None,
        )

    @property
    def identity(self) -> tuple[str, str]:
        return self.service_type, self.instance_name

    @property
    def interfaces(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    item.interface
                    for item in self.provenance
                    if item.interface is not None
                }
            )
        )


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
    service_type: str | None = None
    instance_name: str | None = None
    port_resolved: bool | None = None


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
