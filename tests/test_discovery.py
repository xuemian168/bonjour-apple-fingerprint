from types import SimpleNamespace

import pytest
from zeroconf import InterfaceChoice

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


def test_listener_ignores_unresolved_service_info():
    zc = SimpleNamespace(get_service_info=lambda *args, **kwargs: None)
    listener = ObservationListener()

    listener.add_service(zc, "_rfb._tcp.local.", "Desk._rfb._tcp.local.")

    assert listener.devices() == ()


def test_listener_removes_observation_by_instance_name():
    listener = ObservationListener()
    listener.add_service(
        FakeZeroconf(), "_rfb._tcp.local.", "Desk._rfb._tcp.local."
    )

    listener.remove_service(
        FakeZeroconf(), "_rfb._tcp.local.", "Desk._rfb._tcp.local."
    )

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
    monkeypatch.setattr(discovery.time, "monotonic", _clock([1.0, 1.0, 1.05]))
    monkeypatch.setattr(
        discovery.time, "sleep", lambda seconds: events.append(("sleep", seconds))
    )

    assert discover(0.05, service_types=("_rfb._tcp.local.",)) == ()
    assert events[0] == ("zc", InterfaceChoice.All, False)
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
        discovery, "resolve_interface_addresses", lambda name: ["10.0.0.2"]
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
