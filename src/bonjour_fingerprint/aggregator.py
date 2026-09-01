from .models import DeviceRecord, ServiceObservation, canonical_dns_name


class DeviceAggregator:
    def __init__(self) -> None:
        self._devices: dict[str, DeviceRecord] = {}
        self._owners: dict[tuple[str, str], set[str]] = {}

    def add(self, observation: ServiceObservation) -> None:
        identity = observation.identity
        owners = self._owners.setdefault(identity, set())
        device = self._devices.setdefault(
            observation.server, DeviceRecord(server=observation.server)
        )
        device.services[identity] = observation
        owners.add(observation.server)
        self._rebuild(observation.server)

    def replace(
        self, observation: ServiceObservation, *, previous_server: str
    ) -> None:
        """Retarget one known owner without disturbing parallel announcements."""
        self.remove(*observation.identity, server=previous_server)
        self.add(observation)

    def remove(
        self, service_type: str, instance_name: str, *, server: str | None = None
    ) -> None:
        """Remove one owner, or all owners when no server is specified."""
        identity = ServiceObservation(
            service_type=service_type,
            instance_name=instance_name,
            server="",
            port=0,
        ).identity
        servers = self._owners.get(identity)
        if servers is None:
            return
        targets = set(servers)
        if server is not None:
            targets.intersection_update({canonical_dns_name(server)})
        for target in targets:
            self._devices[target].services.pop(identity, None)
            servers.remove(target)
            self._rebuild(target)
        if not servers:
            del self._owners[identity]

    def devices(self) -> tuple[DeviceRecord, ...]:
        return tuple(self._devices[key] for key in sorted(self._devices))

    def _rebuild(self, server: str) -> None:
        device = self._devices[server]
        if not device.services:
            del self._devices[server]
            return
        device.addresses = {
            address for service in device.services.values() for address in service.addresses
        }
        device.interfaces = {
            service.interface for service in device.services.values() if service.interface
        }
