import json

from bonjour_fingerprint import cli
from bonjour_fingerprint.aggregator import DeviceAggregator
from bonjour_fingerprint.models import ServiceObservation


def device_with(*observations: ServiceObservation):
    aggregator = DeviceAggregator()
    for observation in observations:
        aggregator.add(observation)
    return aggregator.devices()[0]


def service(
    service_type: str,
    instance_name: str,
    *,
    server: str = "desk.local.",
    port: int = 5900,
    addresses: tuple[str, ...] = ("10.147.17.140",),
    properties: dict[str, str] | None = None,
    interface: str | None = "en0",
    port_resolved: bool = True,
) -> ServiceObservation:
    return ServiceObservation(
        service_type=service_type,
        instance_name=instance_name,
        server=server,
        port=port,
        addresses=addresses,
        properties=properties or {},
        interface=interface,
        port_resolved=port_resolved,
    )


def test_json_output_is_machine_readable(monkeypatch, capsys):
    macbook_device = device_with(
        service("_rfb._tcp.local.", "MacBook Pro Plus Max Ultra")
    )
    monkeypatch.setattr(
        cli, "discover", lambda duration, interface=None: (macbook_device,)
    )

    assert cli.main(["scan", "--duration", "1", "--json"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["category"] == "MacBook Pro"
    assert payload[0]["model"] == "unknown"
    assert payload[0]["addresses"] == ["10.147.17.140"]
    assert payload[0]["completeness"] == {"complete": True, "issues": []}


def test_json_preserves_service_address_interface_provenance(monkeypatch, capsys):
    device = device_with(
        service(
            "_rfb._tcp.local.",
            "Desk",
            addresses=("10.0.0.20",),
            interface="en0",
        ),
        service(
            "_rfb._tcp.local.",
            "Desk",
            addresses=("10.0.1.20",),
            interface="en1",
        ),
    )
    monkeypatch.setattr(cli, "discover", lambda duration, interface=None: (device,))

    assert cli.main(["scan", "--duration", "1", "--json"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["services"][0]["provenance"] == [
        {
            "interface": "en0",
            "addresses": ["10.0.0.20"],
            "port": 5900,
            "port_resolved": True,
        },
        {
            "interface": "en1",
            "addresses": ["10.0.1.20"],
            "port": 5900,
            "port_resolved": True,
        },
    ]


def test_text_output_lists_confidence_evidence_missing_and_conflicts(
    monkeypatch, capsys
):
    macbook_device = device_with(
        service(
            "_rfb._tcp.local.",
            "MacBook Pro Plus Max Ultra",
            properties={"am": "Mac17,9"},
        ),
        service(
            "_device-info._tcp.local.",
            "Desk",
            port=7000,
            properties={"am": "Mac14,7"},
        ),
    )
    monkeypatch.setattr(
        cli, "discover", lambda duration, interface=None: (macbook_device,)
    )

    assert cli.main(["scan", "--duration", "1"]) == 0

    output = capsys.readouterr().out
    assert "  confidence: low" in output
    assert "[medium] service: _rfb._tcp.local. on port 5900" in output
    assert "[medium] instance name: MacBook Pro" in output
    assert "[high] _device-info._tcp.local. TXT am: Mac14,7" in output
    assert "[high] _rfb._tcp.local. TXT am: Mac17,9" in output
    assert "  conflicts: Mac14,7, Mac17,9" in output

    missing_device = device_with(
        service("_rfb._tcp.local.", "MacBook Pro Plus Max Ultra")
    )
    monkeypatch.setattr(
        cli, "discover", lambda duration, interface=None: (missing_device,)
    )
    assert cli.main(["scan", "--duration", "1"]) == 0
    assert (
        "  missing: explicit Apple model identifier" in capsys.readouterr().out
    )


def test_empty_result_is_successful(monkeypatch, capsys):
    monkeypatch.setattr(cli, "discover", lambda duration, interface=None: ())

    assert cli.main(["scan", "--duration", "0.1", "--interface", "en0"]) == 0

    assert (
        "No Apple Bonjour devices observed in 0.1s on en0."
        in capsys.readouterr().out
    )


def test_discovery_error_returns_exit_two(monkeypatch, capsys):
    def fail(duration, interface=None):
        raise cli.DiscoveryError("interface en9 not found")

    monkeypatch.setattr(cli, "discover", fail)

    assert cli.main(["scan", "--interface", "en9"]) == 2

    assert "interface en9 not found" in capsys.readouterr().err


def test_json_marks_partial_discovery_without_exposing_synthetic_values(
    monkeypatch, capsys
):
    partial_device = device_with(
        service(
            "_rfb._tcp.local.",
            "MacBook Pro",
            server="unresolved-a1b2.invalid.",
            port=0,
            addresses=(),
            interface=None,
            port_resolved=False,
        )
    )
    monkeypatch.setattr(
        cli, "discover", lambda duration, interface=None: (partial_device,)
    )

    assert cli.main(["scan", "--duration", "1", "--json"]) == 0

    output = capsys.readouterr().out
    payload = json.loads(output)
    assert payload[0]["server"] is None
    assert payload[0]["addresses"] == []
    assert payload[0]["services"][0]["port"] is None
    assert payload[0]["model"] == "unknown"
    assert payload[0]["completeness"] == {
        "complete": False,
        "issues": [
            "unresolved server",
            "missing addresses",
            "unresolved service port",
        ],
    }
    assert "unresolved-a1b2.invalid" not in output
    assert "port 0" not in output


def test_text_marks_partial_discovery_without_exposing_synthetic_values(
    monkeypatch, capsys
):
    partial_device = device_with(
        service(
            "_rfb._tcp.local.",
            "MacBook Pro",
            server="unresolved-a1b2.invalid.",
            port=0,
            addresses=(),
            interface=None,
            port_resolved=False,
        )
    )
    monkeypatch.setattr(
        cli, "discover", lambda duration, interface=None: (partial_device,)
    )

    assert cli.main(["scan", "--duration", "1"]) == 0

    output = capsys.readouterr().out
    assert "unresolved (incomplete discovery record)" in output
    assert (
        "completeness: incomplete (unresolved server, missing addresses, "
        "unresolved service port)" in output
    )
    assert "_rfb._tcp.local. MacBook Pro :unresolved" in output
    assert "[medium] service: _rfb._tcp.local. with unresolved port" in output
    assert "  model: unknown" in output
    assert "unresolved-a1b2.invalid" not in output
    assert ":0" not in output
    assert "port 0" not in output
