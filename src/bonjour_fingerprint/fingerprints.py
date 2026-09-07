from collections.abc import Mapping
from importlib.resources import files
from pathlib import Path

from .catalog import CatalogEntry, CatalogValue, coerce_entry, load_catalog
from .models import (
    ClassificationResult,
    Confidence,
    DeviceRecord,
    Evidence,
    ModelCandidate,
    ServiceObservation,
)


MODEL_KEYS = ("am", "model")
FAMILY_CATEGORIES = {
    "appletv": "Apple TV",
    "apple tv": "Apple TV",
    "homepod": "HomePod",
    "iphone": "iPhone",
    "ipad": "iPad",
}


def load_model_catalog(path: Path | None = None) -> dict[str, CatalogEntry]:
    resource = path or files("bonjour_fingerprint").joinpath("data/apple_models.json")
    return load_catalog(resource)


def classify(
    device: DeviceRecord, catalog: Mapping[str, CatalogValue]
) -> ClassificationResult:
    services = tuple(
        sorted(
            device.services.values(),
            key=lambda service: (service.service_type, service.instance_name, service.port),
        )
    )
    names = " ".join(service.instance_name.lower() for service in services)
    category, category_evidence = _category(names, services)
    identifier_sources: dict[str, set[str]] = {}

    for service in services:
        for key in MODEL_KEYS:
            identifier = service.properties.get(key)
            if identifier is not None:
                identifier = identifier.strip()
                if not identifier:
                    continue
                source = f"{service.service_type} TXT {key}"
                identifier_sources.setdefault(identifier, set()).add(source)

    identifier_evidence = [
        Evidence(
            source,
            identifier,
            Confidence.HIGH if identifier in catalog else Confidence.LOW,
        )
        for identifier, sources in sorted(identifier_sources.items())
        for source in sorted(sources)
    ]
    evidence = [*category_evidence, *identifier_evidence]
    candidates = tuple(
        ModelCandidate(identifier, name, min(identifier_sources[identifier]))
        for identifier in sorted(identifier_sources)
        if identifier in catalog
        for name in coerce_entry(identifier, catalog[identifier]).names
    )

    if len(identifier_sources) > 1:
        return ClassificationResult(
            device,
            category,
            "unknown",
            Confidence.LOW,
            tuple(evidence),
            candidates=candidates,
            conflicts=tuple(sorted(identifier_sources)),
        )
    if len(identifier_sources) == 1:
        identifier, sources = next(iter(identifier_sources.items()))
        if identifier not in catalog:
            return ClassificationResult(
                device,
                category,
                "unknown",
                Confidence.LOW,
                tuple(evidence),
                missing=("recognized explicit Apple model identifier",),
            )
        source = min(sources)
        entry = coerce_entry(identifier, catalog[identifier])
        candidates = tuple(
            ModelCandidate(identifier, name, source) for name in entry.names
        )
        category = entry.category or category
        if len(candidates) > 1:
            return ClassificationResult(
                device,
                category,
                f"{category} (multiple possible models)",
                Confidence.MEDIUM,
                tuple(evidence),
                candidates=candidates,
                missing=("unique model mapping",),
            )
        candidate = candidates[0]
        category = entry.category or _category_from_model(candidate.name) or category
        return ClassificationResult(
            device,
            category,
            candidate.name,
            Confidence.HIGH,
            tuple(evidence),
            candidates=(candidate,),
        )

    confidence = (
        Confidence.MEDIUM
        if len(_independent_category_signals(category_evidence)) >= 2
        else Confidence.LOW
    )
    return ClassificationResult(
        device,
        category,
        "unknown",
        confidence,
        tuple(evidence),
        missing=("explicit Apple model identifier",),
    )


def _category(
    names: str, services: tuple[ServiceObservation, ...]
) -> tuple[str, tuple[Evidence, ...]]:
    evidence: list[Evidence] = []
    for service in services:
        if service.service_type == "_raop._tcp.local.":
            evidence.append(_service_evidence(service, Confidence.MEDIUM))
        if service.service_type == "_rfb._tcp.local.":
            evidence.append(_service_evidence(service, Confidence.MEDIUM))
    family_categories: dict[str, list[tuple[str, str]]] = {}
    for service in services:
        family = service.properties.get("md", "").strip()
        category = FAMILY_CATEGORIES.get(family.lower())
        if category:
            family_categories.setdefault(category, []).append(
                (f"{service.service_type} TXT md", family)
            )
    if len(family_categories) == 1:
        category, sources = next(iter(family_categories.items()))
        evidence.extend(
            Evidence(source, family, Confidence.MEDIUM)
            for source, family in sorted(sources)
        )
        name_token = category.lower()
        if name_token in names:
            evidence.append(Evidence("instance name", category, Confidence.MEDIUM))
        return category, tuple(evidence)
    if "macbook pro" in names:
        evidence.append(Evidence("instance name", "MacBook Pro", Confidence.MEDIUM))
        return "MacBook Pro", tuple(evidence)
    if "iphone" in names:
        evidence.append(Evidence("instance name", "iPhone", Confidence.MEDIUM))
        return "iPhone", tuple(evidence)
    if "ipad" in names:
        evidence.append(Evidence("instance name", "iPad", Confidence.MEDIUM))
        return "iPad", tuple(evidence)
    if "homepod" in names:
        evidence.append(Evidence("instance name", "HomePod", Confidence.MEDIUM))
    if "homepod" in names or any(
        service.service_type == "_raop._tcp.local." for service in services
    ):
        return "Apple audio device", tuple(evidence)
    if any(service.service_type == "_rfb._tcp.local." for service in services):
        return "Mac", tuple(evidence)
    if services:
        service = services[0]
        evidence.append(_service_evidence(service, Confidence.LOW))
        return "Unknown device", tuple(evidence)
    return "Unknown device", ()


def _category_from_model(model_name: str) -> str | None:
    normalized = model_name.lower()
    for prefix, category in (
        ("macbook pro", "MacBook Pro"),
        ("iphone", "iPhone"),
        ("ipad", "iPad"),
        ("apple tv", "Apple TV"),
        ("homepod", "HomePod"),
    ):
        if normalized.startswith(prefix):
            return category
    return None


def _independent_category_signals(
    evidence: tuple[Evidence, ...],
) -> set[str]:
    signals: set[str] = set()
    for item in evidence:
        if item.source == "service":
            signals.add("service")
        elif item.source == "instance name":
            signals.add("instance name")
        elif item.source.endswith(" TXT md"):
            signals.add("product family")
    return signals


def _service_evidence(
    service: ServiceObservation, strength: Confidence
) -> Evidence:
    value = (
        f"{service.service_type} on port {service.port}"
        if service.port_resolved
        else f"{service.service_type} with unresolved port"
    )
    return Evidence(
        "service",
        value,
        strength,
        service_type=service.service_type,
        instance_name=service.instance_name,
        port_resolved=service.port_resolved,
    )
