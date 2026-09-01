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
