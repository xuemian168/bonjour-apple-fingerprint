import json
from collections.abc import Mapping
from importlib.resources import files
from pathlib import Path

from .models import (
    ClassificationResult,
    Confidence,
    DeviceRecord,
    Evidence,
    ModelCandidate,
)


MODEL_KEYS = ("am", "model")


def load_model_catalog(path: Path | None = None) -> dict[str, str]:
    resource = path or files("bonjour_fingerprint").joinpath("data/apple_models.json")
    with resource.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def classify(device: DeviceRecord, catalog: Mapping[str, str]) -> ClassificationResult:
    evidence: list[Evidence] = []
    identifiers: dict[str, str] = {}
    names = " ".join(service.instance_name.lower() for service in device.services.values())
    service_types = {service.service_type for service in device.services.values()}

    for service in device.services.values():
        for key in MODEL_KEYS:
            identifier = service.properties.get(key)
            if identifier in catalog:
                source = f"{service.service_type} TXT {key}"
                identifiers[identifier] = source
                evidence.append(Evidence(source, identifier, Confidence.HIGH))

    if len(identifiers) > 1:
        return ClassificationResult(
            device,
            _category(names, service_types),
            "unknown",
            Confidence.LOW,
            tuple(evidence),
            conflicts=tuple(sorted(identifiers)),
        )
    if len(identifiers) == 1:
        identifier, source = next(iter(identifiers.items()))
        candidate = ModelCandidate(identifier, catalog[identifier], source)
        return ClassificationResult(
            device,
            _category(names, service_types),
            candidate.name,
            Confidence.HIGH,
            tuple(evidence),
            candidates=(candidate,),
        )

    category = _category(names, service_types)
    if "_rfb._tcp.local." in service_types:
        evidence.append(Evidence("service", "_rfb._tcp on port 5900", Confidence.MEDIUM))
    if "macbook pro" in names:
        evidence.append(Evidence("instance name", "MacBook Pro", Confidence.MEDIUM))
    confidence = Confidence.MEDIUM if len(evidence) >= 2 else Confidence.LOW
    return ClassificationResult(
        device,
        category,
        "unknown",
        confidence,
        tuple(evidence),
        missing=("explicit Apple model identifier",),
    )


def _category(names: str, service_types: set[str]) -> str:
    if "macbook pro" in names:
        return "MacBook Pro"
    if "iphone" in names:
        return "iPhone"
    if "homepod" in names or "_raop._tcp.local." in service_types:
        return "Apple audio device"
    if "_rfb._tcp.local." in service_types:
        return "Mac"
    return "Apple device candidate"
