import json
import re
from pathlib import Path

import pytest

from bonjour_fingerprint.aggregator import DeviceAggregator
from bonjour_fingerprint.fingerprints import classify, load_model_catalog
from bonjour_fingerprint.models import Confidence, ModelCandidate, ServiceObservation
from bonjour_fingerprint.render import render_text, result_to_dict


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


def service(kind, name="Desk", properties=None, port=0, port_resolved=True):
    return ServiceObservation(
        kind,
        name,
        "desk.local.",
        port,
        ("10.0.0.2",),
        properties or {},
        "en0",
        port_resolved,
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
    assert result.confidence is Confidence.LOW
    assert result.conflicts == ("Mac17,9", "Mac99,1")
    assert result.candidates == (
        ModelCandidate(
            "Mac17,9",
            "MacBook Pro (14-inch, M5 Pro, 2026)",
            "_device-info._tcp.local. TXT am",
        ),
        ModelCandidate("Mac99,1", "Imaginary Mac", "_airplay._tcp.local. TXT am"),
    )


def test_known_and_unrecognized_explicit_identifiers_are_a_conflict():
    device = device_with(
        service("_device-info._tcp.local.", name="One", properties={"am": "Mac17,9"}),
        service("_airplay._tcp.local.", name="Two", properties={"am": "Mac99,1"}),
    )

    result = classify(device, CATALOG)

    assert result.model == "unknown"
    assert result.confidence is Confidence.LOW
    assert result.conflicts == ("Mac17,9", "Mac99,1")
    assert result.candidates == (
        ModelCandidate(
            "Mac17,9",
            "MacBook Pro (14-inch, M5 Pro, 2026)",
            "_device-info._tcp.local. TXT am",
        ),
    )
    assert any(item.value == "Mac99,1" for item in result.evidence)


def test_unrecognized_identifier_is_observed_but_recognized_identifier_is_missing():
    result = classify(
        device_with(
            service(
                "_device-info._tcp.local.", properties={"am": "UnmappedDevice1,1"}
            )
        ),
        CATALOG,
    )

    assert result.missing == ("recognized explicit Apple model identifier",)
    assert any(item.value == "UnmappedDevice1,1" for item in result.evidence)


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


def test_ipad_instance_name_supports_category_without_claiming_exact_model():
    result = classify(
        device_with(service("_airplay._tcp.local.", name="Mina's iPad")), CATALOG
    )

    assert result.category == "iPad"
    assert result.model == "unknown"
    assert result.confidence is Confidence.LOW


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


def test_duplicate_same_kind_advertisements_do_not_inflate_confidence():
    result = classify(
        device_with(
            service("_raop._tcp.local.", name="Living Room A", port=7000),
            service("_raop._tcp.local.", name="Living Room B", port=7000),
        ),
        CATALOG,
    )

    assert result.category == "Apple audio device"
    assert result.confidence is Confidence.LOW


def test_product_family_aliases_do_not_count_as_independent_signal_classes():
    result = classify(
        device_with(
            service(
                "_airplay._tcp.local.",
                name="Living Room",
                properties={"md": "AppleTV"},
            ),
            service(
                "_companion-link._tcp.local.",
                name="Den",
                properties={"md": "Apple TV"},
            ),
        ),
        CATALOG,
    )

    assert result.category == "Apple TV"
    assert result.confidence is Confidence.LOW


def test_resolved_srv_port_zero_is_preserved_and_not_incomplete():
    result = classify(
        device_with(service("_device-info._tcp.local.", port=0)),
        CATALOG,
    )

    payload = result_to_dict(result)
    assert payload["services"][0]["port"] == 0
    assert payload["completeness"] == {"complete": True, "issues": []}


def test_mixed_port_zero_evidence_preserves_each_observations_resolution_state():
    result = classify(
        device_with(
            service(
                "_rfb._tcp.local.",
                name="Resolved",
                port=0,
                port_resolved=True,
            ),
            service(
                "_rfb._tcp.local.",
                name="Unresolved",
                port=0,
                port_resolved=False,
            ),
        ),
        CATALOG,
    )

    payload = result_to_dict(result)
    service_evidence = [
        item for item in payload["evidence"] if item["source"] == "service"
    ]
    assert [item["value"] for item in service_evidence] == [
        "_rfb._tcp.local. on port 0",
        "_rfb._tcp.local. with unresolved port",
    ]
    assert [item["observation"]["name"] for item in service_evidence] == [
        "Resolved",
        "Unresolved",
    ]
    output = render_text([result], duration=1, interface="en0")
    assert output.count("on port 0") == 1
    assert output.count("with unresolved port") == 1


@pytest.mark.parametrize(
    ("fixture_name", "case_name"),
    [
        ("macbook_rfb_only.json", None),
        ("mac_explicit_model.json", None),
        ("apple_devices.json", "iphone"),
        ("apple_devices.json", "apple-tv"),
        ("apple_devices.json", "homepod"),
        ("adversarial_txt.json", None),
        ("non_apple_generic.json", None),
        ("conflicting_models.json", None),
        ("ipad_devices.json", "category-only"),
        ("ipad_devices.json", "explicit-model"),
    ],
    ids=[
        "macbook-rfb-only",
        "explicit-model",
        "iphone",
        "apple-tv",
        "homepod",
        "adversarial",
        "non-apple-generic",
        "conflicting-models",
        "ipad-category-only",
        "ipad-explicit-model",
    ],
)
def test_realistic_fixture_classification(fixture_name, case_name):
    fixture, result = classify_fixture(fixture_name, case_name)

    actual = {
        "category": result.category,
        "model": result.model,
        "confidence": result.confidence.value,
    }
    expected = fixture["expected"]

    assert actual == {key: expected[key] for key in actual}
    if "conflicts" in expected:
        assert list(result.conflicts) == expected["conflicts"]


def test_adversarial_fixture_renders_without_control_characters():
    _, result = classify_fixture("adversarial_txt.json")

    output = render_text([result], duration=1, interface="en0")

    assert UNSAFE_RENDERED_CONTROLS.search(output) is None
