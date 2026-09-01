from bonjour_fingerprint.models import ServiceObservation
from bonjour_fingerprint.sanitize import sanitize_text


def test_sanitize_text_removes_terminal_controls_and_caps_length():
    value = "Mac\x1b[31mBook\n" + "x" * 600
    cleaned = sanitize_text(value)
    assert "\x1b" not in cleaned
    assert "\n" not in cleaned
    assert len(cleaned) == 512


def test_service_observation_normalizes_untrusted_fields():
    observation = ServiceObservation(
        service_type="_rfb._tcp.local.",
        instance_name="Desk\x1b[2J",
        server="desk.local.",
        port=5900,
        addresses=("10.0.0.2",),
        properties={"model": "MacBookPro"},
        interface="en0",
    )
    assert observation.instance_name == "Desk[2J"
    assert observation.identity == ("_rfb._tcp.local.", "Desk[2J")


def test_service_observation_canonicalizes_dns_target_and_service_type():
    observation = ServiceObservation(
        service_type="_RFB._TCP.LOCAL",
        instance_name="Desk",
        server="DESK.Local",
        port=5900,
    )

    assert observation.service_type == "_rfb._tcp.local."
    assert observation.server == "desk.local."


def test_dns_canonicalization_does_not_exceed_untrusted_input_cap():
    observation = ServiceObservation(
        service_type="x" * 512,
        instance_name="Desk",
        server="y" * 512,
        port=5900,
    )

    assert len(observation.service_type) == 512
    assert len(observation.server) == 512
    assert observation.service_type.endswith(".")
    assert observation.server.endswith(".")
