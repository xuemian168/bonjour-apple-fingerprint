from types import SimpleNamespace

import pytest
from bonjour_fingerprint import discovery
from bonjour_fingerprint.discovery import (
    APPLE_SERVICE_TYPES,
    DiscoveryError,
    ObservationListener,
    discover,
    resolve_interface_addresses,
)


class FakeInfo:
    server = "Desk.local."
    port = 5900
    properties = {b"model": b"MacBookPro", b"flag": None}

    def parsed_scoped_addresses(self):
        return ["10.0.0.2", "fe80::1%en0"]


class FakeZeroconf:
    timeout = None

    def get_service_info(self, service_type, name, timeout=3000):
        self.timeout = timeout
        return FakeInfo()


def test_listener_converts_service_info_to_normalized_observation():
    listener = ObservationListener(interface="en0")
    zc = FakeZeroconf()

    listener.add_service(zc, "_rfb._tcp.local.", "Desk._rfb._tcp.local.")

    device = listener.devices()[0]
    service = next(iter(device.services.values()))
    assert service.instance_name == "Desk"
    assert service.properties == {"model": "MacBookPro", "flag": ""}
    assert service.addresses == ("10.0.0.2", "fe80::1%en0")
    assert device.interfaces == {"en0"}
    assert zc.timeout == 500


def test_listener_preserves_unresolved_service_with_missing_evidence():
    zc = SimpleNamespace(get_service_info=lambda *args, **kwargs: None)
    listener = ObservationListener()

    listener.add_service(zc, "_rfb._tcp.local.", "Desk._rfb._tcp.local.")

    device = listener.devices()[0]
    service = next(iter(device.services.values()))
    assert device.server == (
        "unresolved-"
        "6dfd50fcd8590e437cc900b31fb2e280dd3d090d00b5a6bf"
        ".invalid."
    )
    assert service.port == 0
    assert service.port_resolved is False
    assert service.addresses == ()
    assert service.properties == {}


def test_listener_preserves_partial_info_and_replaces_it_when_resolved():
    class PartialInfo:
        server = None
        port = 7000
        properties = {b"model": b"MacBookPro"}

        def parsed_scoped_addresses(self):
            return ["10.0.0.8"]

    answers = iter([PartialInfo(), FakeInfo()])
    zc = SimpleNamespace(
        get_service_info=lambda *args, **kwargs: next(answers)
    )
    listener = ObservationListener(interface="en0")

    listener.add_service(zc, "_rfb._tcp.local.", "Desk._rfb._tcp.local.")

    pending = listener.devices()[0]
    pending_service = next(iter(pending.services.values()))
    assert pending.server.endswith(".invalid.")
    assert pending_service.port == 7000
    assert pending_service.port_resolved is True
    assert pending_service.addresses == ("10.0.0.8",)
    assert pending_service.properties == {"model": "MacBookPro"}

    listener.update_service(zc, "_rfb._tcp.local.", "Desk._rfb._tcp.local.")

    assert [device.server for device in listener.devices()] == ["desk.local."]


def test_listener_update_retargets_and_removal_drops_only_current_owner():
    first = SimpleNamespace(
        server="old.local.",
        port=5900,
        properties={},
        parsed_scoped_addresses=lambda: ["10.0.0.2"],
    )
    second = SimpleNamespace(
        server="new.local.",
        port=5900,
        properties={},
        parsed_scoped_addresses=lambda: ["10.0.0.3"],
    )
    answers = iter([first, second])
    zc = SimpleNamespace(get_service_info=lambda *args, **kwargs: next(answers))
    listener = ObservationListener(interface="en0")

    listener.add_service(zc, "_rfb._tcp.local.", "Desk._rfb._tcp.local.")
    listener.update_service(zc, "_rfb._tcp.local.", "Desk._rfb._tcp.local.")

    assert [device.server for device in listener.devices()] == ["new.local."]
    listener.remove_service(zc, "_rfb._tcp.local.", "Desk._rfb._tcp.local.")
    assert listener.devices() == ()


def test_listener_removal_clears_all_ambiguous_same_identity_owners():
    answers = iter(
        [
            SimpleNamespace(
                server="one.local.",
                port=5900,
                properties={},
                parsed_scoped_addresses=lambda: ["10.0.0.2"],
            ),
            SimpleNamespace(
                server="two.local.",
                port=5900,
                properties={},
                parsed_scoped_addresses=lambda: ["10.0.0.3"],
            ),
        ]
    )
    zc = SimpleNamespace(get_service_info=lambda *args, **kwargs: next(answers))
    listener = ObservationListener(interface="en0")

    listener.add_service(zc, "_rfb._tcp.local.", "Desk._rfb._tcp.local.")
    listener.add_service(zc, "_rfb._tcp.local.", "Desk._rfb._tcp.local.")
    assert [device.server for device in listener.devices()] == [
        "one.local.",
        "two.local.",
    ]

    listener.remove_service(zc, "_rfb._tcp.local.", "Desk._rfb._tcp.local.")

    assert listener.devices() == ()


def test_ambiguous_update_preserves_all_possible_prior_owners_until_removal():
    def info(server, address):
        return SimpleNamespace(
            server=server,
            port=5900,
            properties={},
            parsed_scoped_addresses=lambda: [address],
        )

    answers = iter(
        [
            info("one.local.", "10.0.0.2"),
            info("two.local.", "10.0.0.3"),
            info("three.local.", "10.0.0.4"),
        ]
    )
    zc = SimpleNamespace(get_service_info=lambda *args, **kwargs: next(answers))
    listener = ObservationListener(interface="en0")

    listener.add_service(zc, "_rfb._tcp.local.", "Desk._rfb._tcp.local.")
    listener.add_service(zc, "_rfb._tcp.local.", "Desk._rfb._tcp.local.")
    listener.update_service(zc, "_rfb._tcp.local.", "Desk._rfb._tcp.local.")

    assert [device.server for device in listener.devices()] == [
        "one.local.",
        "three.local.",
        "two.local.",
    ]


def test_listener_treats_srv_port_zero_as_resolved_observation():
    info = SimpleNamespace(
        server="desk.local.",
        port=0,
        properties={},
        parsed_scoped_addresses=lambda: ["10.0.0.2"],
    )
    listener = ObservationListener(interface="en0")

    listener.add_service(
        SimpleNamespace(get_service_info=lambda *args, **kwargs: info),
        "_device-info._tcp.local.",
        "Desk._device-info._tcp.local.",
    )

    service = next(iter(listener.devices()[0].services.values()))
    assert service.port == 0
    assert service.port_resolved is True


def test_listener_does_not_recreate_pending_record_after_resolution():
    answers = iter([FakeInfo(), None])
    zc = SimpleNamespace(
        get_service_info=lambda *args, **kwargs: next(answers)
    )
    listener = ObservationListener()
    listener.add_service(zc, "_rfb._tcp.local.", "Desk._rfb._tcp.local.")

    listener.update_service(zc, "_rfb._tcp.local.", "Desk._rfb._tcp.local.")

    assert [device.server for device in listener.devices()] == ["desk.local."]


def test_listener_removes_observation_by_instance_name():
    listener = ObservationListener()
    listener.add_service(
        FakeZeroconf(), "_rfb._tcp.local.", "Desk._rfb._tcp.local."
    )

    listener.remove_service(
        FakeZeroconf(), "_rfb._tcp.local.", "Desk._rfb._tcp.local."
    )

    assert listener.devices() == ()


def test_listener_remove_uses_sanitized_observation_identity():
    service_type = "_rfb.\x1b_tcp.local."
    name = "Desk\x07." + service_type
    listener = ObservationListener()
    listener.add_service(FakeZeroconf(), service_type, name)

    listener.remove_service(FakeZeroconf(), service_type, name)

    assert listener.devices() == ()


def test_resolve_interface_addresses_returns_non_link_local_ipv4(monkeypatch):
    adapter = SimpleNamespace(
        name="en0",
        nice_name="Wi-Fi",
        ips=[
            SimpleNamespace(ip="10.0.0.2"),
            SimpleNamespace(ip="169.254.10.20"),
            SimpleNamespace(ip=("fe80::1", 0, 0)),
        ],
    )
    monkeypatch.setattr(discovery.ifaddr, "get_adapters", lambda: [adapter])

    assert resolve_interface_addresses("en0") == ["10.0.0.2"]
    assert resolve_interface_addresses("Wi-Fi") == ["10.0.0.2"]


def test_resolve_interface_addresses_rejects_unknown_interface(monkeypatch):
    adapter = SimpleNamespace(name="en0", nice_name="Wi-Fi", ips=[])
    monkeypatch.setattr(discovery.ifaddr, "get_adapters", lambda: [adapter])

    with pytest.raises(
        DiscoveryError, match="unknown interface.*missing.*available.*en0.*Wi-Fi"
    ):
        resolve_interface_addresses("missing")


def test_resolve_interface_addresses_returns_empty_for_interface_without_ipv4(
    monkeypatch,
):
    adapter = SimpleNamespace(
        name="en0",
        nice_name="Wi-Fi",
        ips=[SimpleNamespace(ip="169.254.10.20")],
    )
    monkeypatch.setattr(discovery.ifaddr, "get_adapters", lambda: [adapter])

    assert resolve_interface_addresses("en0") == []


def test_default_interface_resolution_returns_concrete_adapter_names(monkeypatch):
    adapters = [
        SimpleNamespace(
            name="en0",
            nice_name="Wi-Fi",
            ips=[SimpleNamespace(ip="10.0.0.2")],
        ),
        SimpleNamespace(
            name="en1",
            nice_name="Ethernet",
            ips=[SimpleNamespace(ip="10.0.1.2")],
        ),
    ]
    monkeypatch.setattr(discovery.ifaddr, "get_adapters", lambda: adapters)

    assert discovery.resolve_discovery_interfaces() == [
        ("en0", ["10.0.0.2"]),
        ("en1", ["10.0.1.2"]),
    ]


@pytest.mark.parametrize("duration", [0, -1, float("nan"), float("inf")])
def test_discover_rejects_invalid_duration(duration):
    with pytest.raises(
        DiscoveryError, match="duration must be a finite positive number"
    ):
        discover(duration)


def test_discover_browses_requested_services_and_cleans_up(monkeypatch):
    events = []

    class LocalZeroconf:
        def __init__(self, *, interfaces, unicast):
            events.append(("zc", interfaces, unicast))

        def close(self):
            events.append("zc.close")

    class LocalBrowser:
        def __init__(self, zc, service_types, *, listener):
            events.append(("browser", tuple(service_types), listener))

        def cancel(self):
            events.append("browser.cancel")

    monkeypatch.setattr(discovery, "Zeroconf", LocalZeroconf)
    monkeypatch.setattr(discovery, "ServiceBrowser", LocalBrowser)
    monkeypatch.setattr(
        discovery,
        "resolve_discovery_interfaces",
        lambda name=None: [("en0", ["10.0.0.2"])],
    )
    monkeypatch.setattr(discovery.time, "monotonic", _clock([1.0, 1.0, 1.05]))
    monkeypatch.setattr(
        discovery.time, "sleep", lambda seconds: events.append(("sleep", seconds))
    )

    assert discover(0.05, service_types=("_rfb._tcp.local.",)) == ()
    assert events[0] == ("zc", ["10.0.0.2"], False)
    assert events[1][0:2] == ("browser", ("_rfb._tcp.local.",))
    assert isinstance(events[1][2], ObservationListener)
    sleep_event = next(
        event
        for event in events
        if isinstance(event, tuple) and event[0] == "sleep"
    )
    assert sleep_event[1] == pytest.approx(0.05)
    assert events[-2:] == ["browser.cancel", "zc.close"]


def test_discover_uses_resolved_interface_address(monkeypatch):
    received = {}

    class LocalZeroconf:
        def __init__(self, *, interfaces, unicast):
            received["interfaces"] = interfaces
            received["unicast"] = unicast

        def close(self):
            pass

    class LocalBrowser:
        def __init__(self, zc, service_types, *, listener):
            received["listener"] = listener

        def cancel(self):
            pass

    monkeypatch.setattr(
        discovery,
        "resolve_discovery_interfaces",
        lambda name=None: [("en0", ["10.0.0.2"])],
    )
    monkeypatch.setattr(discovery, "Zeroconf", LocalZeroconf)
    monkeypatch.setattr(discovery, "ServiceBrowser", LocalBrowser)
    monkeypatch.setattr(discovery.time, "monotonic", _clock([2.0, 2.0, 2.01]))
    monkeypatch.setattr(discovery.time, "sleep", lambda seconds: None)

    discover(0.01, interface="en0")

    assert received["interfaces"] == ["10.0.0.2"]
    assert received["unicast"] is False
    received["listener"].add_service(
        FakeZeroconf(), "_rfb._tcp.local.", "Desk._rfb._tcp.local."
    )
    assert received["listener"].devices()[0].interfaces == {"en0"}


def test_default_discovery_preserves_concrete_interface_provenance(monkeypatch):
    listeners = []

    class LocalZeroconf:
        def __init__(self, *, interfaces, unicast):
            self.interfaces = interfaces

        def close(self):
            pass

        def get_service_info(self, service_type, name, timeout=3000):
            address = "10.0.0.20" if self.interfaces == ["10.0.0.2"] else "10.0.1.20"
            return SimpleNamespace(
                server="desk.local.",
                port=5900,
                properties={},
                parsed_scoped_addresses=lambda: [address],
            )

    class LocalBrowser:
        def __init__(self, zc, service_types, *, listener):
            listeners.append(listener)
            listener.add_service(zc, service_types[0], f"Desk.{service_types[0]}")

        def cancel(self):
            pass

    monkeypatch.setattr(
        discovery,
        "resolve_discovery_interfaces",
        lambda name=None: [("en0", ["10.0.0.2"]), ("en1", ["10.0.1.2"])],
    )
    monkeypatch.setattr(discovery, "Zeroconf", LocalZeroconf)
    monkeypatch.setattr(discovery, "ServiceBrowser", LocalBrowser)
    monkeypatch.setattr(discovery.time, "monotonic", _clock([3.0, 3.0, 3.01]))
    monkeypatch.setattr(discovery.time, "sleep", lambda seconds: None)

    devices = discover(0.01, service_types=("_rfb._tcp.local.",))

    assert len(listeners) == 2
    assert len(devices) == 1
    assert devices[0].interfaces == {"en0", "en1"}
    assert devices[0].addresses == {"10.0.0.20", "10.0.1.20"}
    service = next(iter(devices[0].services.values()))
    assert [
        (row.interface, row.addresses) for row in service.provenance
    ] == [
        ("en0", ("10.0.0.20",)),
        ("en1", ("10.0.1.20",)),
    ]


def test_discover_rejects_interface_without_usable_ipv4(monkeypatch):
    adapter = SimpleNamespace(
        name="en0",
        nice_name="Wi-Fi",
        ips=[SimpleNamespace(ip="169.254.10.20")],
    )
    monkeypatch.setattr(discovery.ifaddr, "get_adapters", lambda: [adapter])

    with pytest.raises(
        DiscoveryError, match="interface.*en0.*no usable non-link-local IPv4"
    ):
        discover(1, interface="en0")


def test_discover_returns_partial_results_on_keyboard_interrupt(monkeypatch):
    closed = []

    class LocalZeroconf:
        def __init__(self, *, interfaces, unicast):
            pass

        def close(self):
            closed.append("zc")

    class LocalBrowser:
        def __init__(self, zc, service_types, *, listener):
            listener.add_service(
                FakeZeroconf(), "_rfb._tcp.local.", "Desk._rfb._tcp.local."
            )

        def cancel(self):
            closed.append("browser")

    def interrupt(_seconds):
        raise KeyboardInterrupt

    monkeypatch.setattr(discovery, "Zeroconf", LocalZeroconf)
    monkeypatch.setattr(discovery, "ServiceBrowser", LocalBrowser)
    monkeypatch.setattr(
        discovery,
        "resolve_discovery_interfaces",
        lambda name=None: [("en0", ["10.0.0.2"])],
    )
    monkeypatch.setattr(discovery.time, "monotonic", _clock([4.0, 4.0]))
    monkeypatch.setattr(discovery.time, "sleep", interrupt)

    devices = discover(1)

    assert [device.server for device in devices] == ["desk.local."]
    assert closed == ["browser", "zc"]


def test_discover_converts_zeroconf_initialization_failure(monkeypatch):
    def fail(**kwargs):
        raise OSError("multicast unavailable")

    monkeypatch.setattr(discovery, "Zeroconf", fail)

    with pytest.raises(
        DiscoveryError, match="initialize Bonjour discovery.*multicast unavailable"
    ):
        discover(1)


def test_discover_converts_browser_failure_and_closes_zeroconf(monkeypatch):
    closed = []

    class LocalZeroconf:
        def __init__(self, *, interfaces, unicast):
            pass

        def close(self):
            closed.append("zc")

    def fail(*args, **kwargs):
        raise OSError("browser unavailable")

    monkeypatch.setattr(discovery, "Zeroconf", LocalZeroconf)
    monkeypatch.setattr(discovery, "ServiceBrowser", fail)

    with pytest.raises(
        DiscoveryError, match="start Bonjour browser.*browser unavailable"
    ):
        discover(1)

    assert closed == ["zc"]


def test_default_service_types_cover_expected_apple_protocols():
    assert APPLE_SERVICE_TYPES == (
        "_rfb._tcp.local.",
        "_device-info._tcp.local.",
        "_airplay._tcp.local.",
        "_raop._tcp.local.",
        "_companion-link._tcp.local.",
        "_smb._tcp.local.",
        "_ssh._tcp.local.",
        "_sleep-proxy._udp.local.",
    )


def _clock(values):
    iterator = iter(values)
    return lambda: next(iterator)
