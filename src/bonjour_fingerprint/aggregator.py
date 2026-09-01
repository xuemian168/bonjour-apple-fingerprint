from .models import DeviceRecord, ServiceObservation


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

    def remove(self, service_type: str, instance_name: str) -> None:
        identity = service_type, instance_name
        servers = self._owners.pop(identity, None)
        if servers is None:
            return
        for server in servers:
            self._devices[server].services.pop(identity, None)
            self._rebuild(server)

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
