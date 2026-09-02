import hashlib
import math
import time
from contextlib import suppress
from dataclasses import replace
from ipaddress import IPv4Address

import ifaddr
from zeroconf import ServiceBrowser, ServiceListener, Zeroconf

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
        self._pending: set[tuple[str, str]] = set()
        self._resolved: set[tuple[str, str]] = set()
        self._owners: dict[tuple[str, str], set[str]] = {}

    def add_service(self, zc, service_type: str, name: str) -> None:
        self._update(zc, service_type, name, replace_existing=False)

    def update_service(self, zc, service_type: str, name: str) -> None:
        self._update(zc, service_type, name, replace_existing=True)

    def remove_service(self, zc, service_type: str, name: str) -> None:
        identity = _normalized_identity(service_type, name)
        # The callback contains no target server, so removal is necessarily
        # identity-wide. This avoids stranding an ambiguous simultaneous owner.
        self._owners.pop(identity, None)
        self._aggregator.remove(*identity)
        self._pending.discard(identity)
        self._resolved.discard(identity)

    def devices(self) -> tuple[DeviceRecord, ...]:
        return self._aggregator.devices()

    def _update(
        self, zc, service_type: str, name: str, *, replace_existing: bool
    ) -> None:
        info = zc.get_service_info(
            service_type, name, timeout=_SERVICE_INFO_TIMEOUT_MS
        )
        properties = {
            key: value if value is not None else b""
            for key, value in getattr(info, "properties", {}).items()
        }
        address_parser = getattr(info, "parsed_scoped_addresses", None)
        addresses = tuple(address_parser()) if address_parser is not None else ()
        observation = ServiceObservation(
            service_type=service_type,
            instance_name=_instance_name(name, service_type),
            server=getattr(info, "server", "") or "",
            port=getattr(info, "port", None) or 0,
            addresses=addresses,
            properties=properties,
            interface=self._interface,
            port_resolved=info is not None
            and getattr(info, "port", None) is not None,
        )
        identity = observation.identity
        owners = self._owners.setdefault(identity, set())
        if not observation.server:
            if identity in self._resolved:
                return
            observation = replace(observation, server=_pending_server(identity))
            self._pending.add(identity)
        else:
            self._pending.discard(identity)
            self._resolved.add(identity)
        if replace_existing and observation.server not in owners and len(owners) == 1:
            previous_owner = next(iter(owners))
            self._aggregator.replace(observation, previous_server=previous_owner)
            owners.remove(previous_owner)
        else:
            # With multiple possible owners, the callback does not identify
            # which one changed. Preserve all until an identity-wide removal.
            self._aggregator.add(observation)
        owners.add(observation.server)


def _normalized_identity(service_type: str, name: str) -> tuple[str, str]:
    return ServiceObservation(
        service_type=service_type,
        instance_name=_instance_name(name, service_type),
        server="",
        port=0,
    ).identity


def _pending_server(identity: tuple[str, str]) -> str:
    service_type, instance_name = identity
    digest = hashlib.sha256(
        f"{service_type}\0{instance_name}".encode("utf-8")
    ).hexdigest()[:48]
    return f"unresolved-{digest}.invalid."


def resolve_interface_addresses(name: str) -> list[str]:
    """Return usable IPv4 addresses for a named local interface."""
    bindings = resolve_discovery_interfaces(name)
    return bindings[0][1] if bindings else []


def resolve_discovery_interfaces(
    name: str | None = None,
) -> list[tuple[str, list[str]]]:
    """Return concrete interface/address bindings suitable for sound provenance."""
    try:
        adapters = ifaddr.get_adapters()
    except Exception as exc:
        raise DiscoveryError(f"could not inspect network interfaces: {exc}") from exc

    selected = [
        candidate
        for candidate in adapters
        if name is None or name in (candidate.name, candidate.nice_name)
    ]
    if name is not None and not selected:
        available = ", ".join(
            candidate.name
            if candidate.nice_name == candidate.name
            else f"{candidate.name} ({candidate.nice_name})"
            for candidate in adapters
        )
        raise DiscoveryError(
            f"unknown interface {name!r}; available interfaces: {available or 'none'}"
        )

    bindings: list[tuple[str, list[str]]] = []
    for adapter in selected:
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
        addresses = list(dict.fromkeys(addresses))
        if addresses:
            bindings.append((adapter.name, addresses))
    return bindings


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

    bindings = resolve_discovery_interfaces(interface)
    if interface is not None and not bindings:
        raise DiscoveryError(
            f"interface {interface!r} has no usable non-link-local IPv4 address; "
            "choose another interface"
        )
    if not bindings:
        raise DiscoveryError("no usable non-link-local IPv4 interfaces available")
    listeners: list[ObservationListener] = []
    zeroconfs: list[Zeroconf] = []
    browsers: list[ServiceBrowser] = []
    try:
        for interface_name, addresses in bindings:
            listener = ObservationListener(interface=interface_name)
            listeners.append(listener)
            try:
                zc = Zeroconf(interfaces=addresses, unicast=False)
                zeroconfs.append(zc)
            except Exception as exc:
                raise DiscoveryError(
                    f"failed to initialize Bonjour discovery: {exc}"
                ) from exc

            try:
                browsers.append(
                    ServiceBrowser(zc, list(service_types), listener=listener)
                )
            except Exception as exc:
                raise DiscoveryError(
                    f"failed to start Bonjour browser: {exc}"
                ) from exc

        deadline = time.monotonic() + duration
        while (remaining := deadline - time.monotonic()) > 0:
            time.sleep(min(0.1, remaining))
    except KeyboardInterrupt:
        pass
    finally:
        for browser in browsers:
            with suppress(Exception):
                browser.cancel()
        for zc in zeroconfs:
            with suppress(Exception):
                zc.close()
    return _merge_listener_devices(listeners)


def _merge_listener_devices(
    listeners: list[ObservationListener],
) -> tuple[DeviceRecord, ...]:
    aggregator = DeviceAggregator()
    addresses: dict[str, set[str]] = {}
    interfaces: dict[str, set[str]] = {}
    for listener in listeners:
        for device in listener.devices():
            addresses.setdefault(device.server, set()).update(device.addresses)
            interfaces.setdefault(device.server, set()).update(device.interfaces)
            for service in device.services.values():
                aggregator.add(service)
    devices = aggregator.devices()
    for device in devices:
        device.addresses.update(addresses[device.server])
        device.interfaces.update(interfaces[device.server])
    return devices


def _instance_name(name: str, service_type: str) -> str:
    clean_name = str(name).rstrip(".")
    clean_type = str(service_type).rstrip(".")
    suffix = "." + clean_type
    return (
        clean_name[: -len(suffix)]
        if clean_name.lower().endswith(suffix.lower())
        else clean_name
    )
