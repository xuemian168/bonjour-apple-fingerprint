import math
import time
from contextlib import suppress
from ipaddress import IPv4Address

import ifaddr
from zeroconf import InterfaceChoice, ServiceBrowser, ServiceListener, Zeroconf

from .aggregator import DeviceAggregator
from .models import DeviceRecord, ServiceObservation

APPLE_SERVICE_TYPES = (
    "_rfb._tcp.local.",
    "_device-info._tcp.local.",
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_companion-link._tcp.local.",
    "_smb._tcp.local.",
    "_ssh._tcp.local.",
    "_sleep-proxy._udp.local.",
)

_SERVICE_INFO_TIMEOUT_MS = 500


class DiscoveryError(RuntimeError):
    """Bonjour discovery could not be started with the requested settings."""


class ObservationListener(ServiceListener):
    def __init__(self, interface: str | None = None) -> None:
        self._interface = interface
        self._aggregator = DeviceAggregator()

    def add_service(self, zc, service_type: str, name: str) -> None:
        self._update(zc, service_type, name)

    def update_service(self, zc, service_type: str, name: str) -> None:
        self._update(zc, service_type, name)

    def remove_service(self, zc, service_type: str, name: str) -> None:
        self._aggregator.remove(service_type, _instance_name(name, service_type))

    def devices(self) -> tuple[DeviceRecord, ...]:
        return self._aggregator.devices()

    def _update(self, zc, service_type: str, name: str) -> None:
        info = zc.get_service_info(
            service_type, name, timeout=_SERVICE_INFO_TIMEOUT_MS
        )
        if info is None or not info.server:
            return
        self._aggregator.add(
            ServiceObservation(
                service_type=service_type,
                instance_name=_instance_name(name, service_type),
                server=info.server,
                port=info.port,
                addresses=tuple(info.parsed_scoped_addresses()),
                properties={
                    key: value if value is not None else b""
                    for key, value in info.properties.items()
                },
                interface=self._interface,
            )
        )


def resolve_interface_addresses(name: str) -> list[str]:
    """Return usable IPv4 addresses for a named local interface."""
    try:
        adapters = ifaddr.get_adapters()
    except Exception as exc:
        raise DiscoveryError(f"could not inspect network interfaces: {exc}") from exc

    adapter = next(
        (
            candidate
            for candidate in adapters
            if name in (candidate.name, candidate.nice_name)
        ),
        None,
    )
    if adapter is None:
        available = ", ".join(
            candidate.name
            if candidate.nice_name == candidate.name
            else f"{candidate.name} ({candidate.nice_name})"
            for candidate in adapters
        )
        raise DiscoveryError(
            f"unknown interface {name!r}; available interfaces: {available or 'none'}"
        )

    addresses: list[str] = []
    for candidate in adapter.ips:
        if not isinstance(candidate.ip, str):
            continue
        try:
            address = IPv4Address(candidate.ip)
        except ValueError:
            continue
        if not address.is_link_local:
            addresses.append(str(address))
    return list(dict.fromkeys(addresses))


def discover(
    duration: float,
    service_types: tuple[str, ...] = APPLE_SERVICE_TYPES,
    interface: str | None = None,
) -> tuple[DeviceRecord, ...]:
    """Passively observe Bonjour advertisements on the local link."""
    if (
        not isinstance(duration, (int, float))
        or not math.isfinite(duration)
        or duration <= 0
    ):
        raise DiscoveryError("duration must be a finite positive number")

    addresses = resolve_interface_addresses(interface) if interface is not None else []
    listener = ObservationListener(interface=interface)
    zc = None
    browser = None
    try:
        try:
            zc = Zeroconf(
                interfaces=addresses or InterfaceChoice.All,
                unicast=False,
            )
        except Exception as exc:
            raise DiscoveryError(
                f"failed to initialize Bonjour discovery: {exc}"
            ) from exc

        try:
            browser = ServiceBrowser(zc, list(service_types), listener=listener)
        except Exception as exc:
            raise DiscoveryError(f"failed to start Bonjour browser: {exc}") from exc

        deadline = time.monotonic() + duration
        while (remaining := deadline - time.monotonic()) > 0:
            time.sleep(min(0.1, remaining))
    except KeyboardInterrupt:
        pass
    finally:
        if browser is not None:
            with suppress(Exception):
                browser.cancel()
        if zc is not None:
            with suppress(Exception):
                zc.close()
    return listener.devices()


def _instance_name(name: str, service_type: str) -> str:
    suffix = "." + service_type
    return name[: -len(suffix)] if name.endswith(suffix) else name
