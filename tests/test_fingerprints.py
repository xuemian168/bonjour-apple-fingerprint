import json
import re
from pathlib import Path

import pytest

from bonjour_fingerprint.aggregator import DeviceAggregator
from bonjour_fingerprint.fingerprints import classify, load_model_catalog
from bonjour_fingerprint.models import Confidence, ServiceObservation
from bonjour_fingerprint.render import render_text


CATALOG = {"Mac17,9": "MacBook Pro (14-inch, M5 Pro, 2026)"}
FIXTURES = Path(__file__).with_name("fixtures")
UNSAFE_RENDERED_CONTROLS = re.compile(r"[\x00-\x09\x0b-\x1f\x7f-\x9f]")


def load_fixture(name, case_name=None):
    with (FIXTURES / name).open(encoding="utf-8") as handle:
        fixture = json.load(handle)
    if case_name is None:
        return fixture
    return next(case for case in fixture["cases"] if case["name"] == case_name)


def classify_fixture(name, case_name=None):
    fixture = load_fixture(name, case_name)
    aggregator = DeviceAggregator()
    for observation in fixture["observations"]:
        aggregator.add(
            ServiceObservation(
                **{
                    **observation,
                    "addresses": tuple(observation.get("addresses", ())),
                }
            )
        )
    return fixture, classify(aggregator.devices()[0], load_model_catalog())


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


def test_homepod_category_includes_instance_name_evidence():
    result = classify(
        device_with(service("_airplay._tcp.local.", name="Kitchen HomePod")), CATALOG
    )

    assert result.category == "Apple audio device"
    assert any(
        evidence.source == "instance name"
        and evidence.value == "HomePod"
        and evidence.strength is Confidence.MEDIUM
        for evidence in result.evidence
    )


def test_unsupported_bonjour_service_is_an_unknown_device():
    result = classify(device_with(service("_ssh._tcp.local.", port=22)), CATALOG)

    assert result.category == "Unknown device"
    assert any(
        evidence.source == "service"
        and evidence.value == "_ssh._tcp.local. on port 22"
        for evidence in result.evidence
    )


def test_blank_and_whitespace_identifiers_do_not_create_conflicts():
    result = classify(
        device_with(
            service("_device-info._tcp.local.", properties={"am": "", "model": "  "})
        ),
        CATALOG,
    )

    assert result.model == "unknown"
    assert result.conflicts == ()
    assert all(evidence.value.strip() for evidence in result.evidence)


def test_identifier_values_are_stripped_before_catalog_lookup():
    result = classify(
        device_with(
            service("_device-info._tcp.local.", properties={"am": " Mac17,9 "})
        ),
        CATALOG,
    )

    assert result.model == "MacBook Pro (14-inch, M5 Pro, 2026)"
    assert result.candidates[0].identifier == "Mac17,9"


def test_duplicate_identifier_uses_a_stable_canonical_candidate_source():
    device = device_with(
        service("_alpha._tcp.local.", name="Alpha", properties={"am": "Mac17,9"}),
        service("_zebra._tcp.local.", name="Zulu", properties={"am": "Mac17,9"}),
    )

    result = classify(device, CATALOG)

    assert result.candidates[0].source == "_alpha._tcp.local. TXT am"


@pytest.mark.parametrize(
    ("fixture_name", "case_name"),
    [
        ("macbook_rfb_only.json", None),
        ("mac_explicit_model.json", None),
        ("apple_devices.json", "iphone"),
        ("apple_devices.json", "apple-tv"),
        ("apple_devices.json", "homepod"),
        ("adversarial_txt.json", None),
    ],
    ids=[
        "macbook-rfb-only",
        "explicit-model",
        "iphone",
        "apple-tv",
        "homepod",
        "adversarial",
    ],
)
def test_realistic_fixture_classification(fixture_name, case_name):
    fixture, result = classify_fixture(fixture_name, case_name)

    assert {
        "category": result.category,
        "model": result.model,
        "confidence": result.confidence.value,
    } == fixture["expected"]


def test_adversarial_fixture_renders_without_control_characters():
    _, result = classify_fixture("adversarial_txt.json")

    output = render_text([result], duration=1, interface="en0")

    assert UNSAFE_RENDERED_CONTROLS.search(output) is None
