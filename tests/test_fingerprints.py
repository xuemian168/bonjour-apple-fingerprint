from bonjour_fingerprint.aggregator import DeviceAggregator
from bonjour_fingerprint.fingerprints import classify
from bonjour_fingerprint.models import Confidence, ServiceObservation


CATALOG = {"Mac17,9": "MacBook Pro (14-inch, M5 Pro, 2026)"}


def device_with(*observations):
    aggregator = DeviceAggregator()
    for item in observations:
        aggregator.add(item)
    return aggregator.devices()[0]


def service(kind, name="Desk", properties=None, port=0):
    return ServiceObservation(
        kind, name, "desk.local.", port, ("10.0.0.2",), properties or {}, "en0"
    )


def test_explicit_known_apple_identifier_is_high_confidence():
    result = classify(
        device_with(service("_device-info._tcp.local.", properties={"am": "Mac17,9"})),
        CATALOG,
    )
    assert result.model == "MacBook Pro (14-inch, M5 Pro, 2026)"
    assert result.confidence is Confidence.HIGH


def test_rfb_and_macbook_name_classify_category_but_not_exact_model():
    result = classify(
        device_with(
            service("_rfb._tcp.local.", name="MacBook Pro Plus Max Ultra", port=5999)
        ),
        CATALOG,
    )
    assert result.category == "MacBook Pro"
    assert result.model == "unknown"
    assert result.confidence is Confidence.MEDIUM
    assert "explicit Apple model identifier" in result.missing
    assert any(
        evidence.source == "service"
        and evidence.value == "_rfb._tcp.local. on port 5999"
        for evidence in result.evidence
    )


def test_conflicting_explicit_identifiers_are_not_silently_resolved():
    device = device_with(
        service("_device-info._tcp.local.", name="One", properties={"am": "Mac17,9"}),
        service("_airplay._tcp.local.", name="Two", properties={"am": "Mac99,1"}),
    )
    result = classify(device, {**CATALOG, "Mac99,1": "Imaginary Mac"})
    assert result.model == "unknown"
    assert result.conflicts == ("Mac17,9", "Mac99,1")


def test_known_and_unrecognized_explicit_identifiers_are_a_conflict():
    device = device_with(
        service("_device-info._tcp.local.", name="One", properties={"am": "Mac17,9"}),
        service("_airplay._tcp.local.", name="Two", properties={"am": "Mac99,1"}),
    )

    result = classify(device, CATALOG)

    assert result.model == "unknown"
    assert result.confidence is Confidence.LOW
    assert result.conflicts == ("Mac17,9", "Mac99,1")


def test_iphone_category_includes_instance_name_evidence():
    result = classify(
        device_with(service("_airplay._tcp.local.", name="Ana's iPhone")), CATALOG
    )

    assert result.category == "iPhone"
    assert any(
        evidence.source == "instance name"
        and evidence.value == "iPhone"
        and evidence.strength is Confidence.MEDIUM
        for evidence in result.evidence
    )


def test_raop_category_includes_service_evidence():
    result = classify(
        device_with(service("_raop._tcp.local.", name="Living Room", port=7000)), CATALOG
    )

    assert result.category == "Apple audio device"
    assert any(
        evidence.source == "service"
        and evidence.value == "_raop._tcp.local. on port 7000"
        and evidence.strength is Confidence.MEDIUM
        for evidence in result.evidence
    )


def test_duplicate_identifier_uses_a_stable_canonical_candidate_source():
    device = device_with(
        service("_alpha._tcp.local.", name="Alpha", properties={"am": "Mac17,9"}),
        service("_zebra._tcp.local.", name="Zulu", properties={"am": "Mac17,9"}),
    )

    result = classify(device, CATALOG)

    assert result.candidates[0].source == "_alpha._tcp.local. TXT am"
