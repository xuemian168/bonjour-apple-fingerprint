from collections.abc import Sequence

from .models import ClassificationResult, Evidence


def _has_synthetic_server(result: ClassificationResult) -> bool:
    server = result.device.server.lower().rstrip(".")
    return server == "invalid" or server.endswith(".invalid")


def _completeness_issues(result: ClassificationResult) -> list[str]:
    issues: list[str] = []
    if _has_synthetic_server(result):
        issues.append("unresolved server")
    if not result.device.addresses:
        issues.append("missing addresses")
    if any(not service.port_resolved for service in result.device.services.values()):
        issues.append("unresolved service port")
    return issues


def _evidence_value(result: ClassificationResult, item: Evidence) -> str:
    if item.source != "service":
        return item.value
    for service in result.device.services.values():
        unresolved_value = f"{service.service_type} on port 0"
        if not service.port_resolved and item.value == unresolved_value:
            return f"{service.service_type} with unresolved port"
    return item.value


def result_to_dict(result: ClassificationResult) -> dict[str, object]:
    issues = _completeness_issues(result)
    return {
        "server": None if _has_synthetic_server(result) else result.device.server,
        "addresses": sorted(result.device.addresses),
        "interfaces": sorted(result.device.interfaces),
        "category": result.category,
        "model": result.model,
        "confidence": result.confidence.value,
        "services": [
            {
                "type": service.service_type,
                "name": service.instance_name,
                "port": service.port if service.port_resolved else None,
                "properties": dict(sorted(service.properties.items())),
            }
            for service in sorted(
                result.device.services.values(),
                key=lambda item: (item.service_type, item.instance_name),
            )
        ],
        "evidence": [
            {
                "source": item.source,
                "value": _evidence_value(result, item),
                "strength": item.strength.value,
            }
            for item in result.evidence
        ],
        "candidates": [
            {
                "identifier": item.identifier,
                "name": item.name,
                "source": item.source,
            }
            for item in result.candidates
        ],
        "missing": list(result.missing),
        "conflicts": list(result.conflicts),
        "completeness": {"complete": not issues, "issues": issues},
    }


def render_text(
    results: Sequence[ClassificationResult], duration: float, interface: str | None
) -> str:
    suffix = f" on {interface}" if interface else ""
    if not results:
        return f"No Apple Bonjour devices observed in {duration:g}s{suffix}."

    lines: list[str] = []
    for result in results:
        issues = _completeness_issues(result)
        addresses = ", ".join(sorted(result.device.addresses)) or "unresolved"
        server = (
            "incomplete discovery record"
            if _has_synthetic_server(result)
            else result.device.server
        )
        lines.extend(
            [
                f"{addresses} ({server})",
                f"  category: {result.category}",
                f"  model: {result.model}",
                f"  confidence: {result.confidence.value}",
                (
                    "  completeness: incomplete (" + ", ".join(issues) + ")"
                    if issues
                    else "  completeness: complete"
                ),
                "  services:",
            ]
        )
        for service in sorted(
            result.device.services.values(),
            key=lambda item: (item.service_type, item.instance_name),
        ):
            port = str(service.port) if service.port_resolved else "unresolved"
            lines.append(
                f"    - {service.service_type} {service.instance_name} :{port}"
            )
        lines.append("  evidence:")
        lines.extend(
            f"    - [{item.strength.value}] {item.source}: "
            f"{_evidence_value(result, item)}"
            for item in result.evidence
        )
        if result.missing:
            lines.append("  missing: " + ", ".join(result.missing))
        if result.conflicts:
            lines.append("  conflicts: " + ", ".join(result.conflicts))
    return "\n".join(lines)
