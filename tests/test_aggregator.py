from bonjour_fingerprint.aggregator import DeviceAggregator
from bonjour_fingerprint.models import ServiceObservation


def observation(kind, name, server, address, port, interface="en0"):
    return ServiceObservation(kind, name, server, port, (address,), {}, interface)


def test_aggregates_services_by_canonical_server_and_deduplicates_addresses():
    aggregator = DeviceAggregator()
    aggregator.add(observation("_rfb._tcp.local.", "Desk", "Desk.local.", "10.0.0.2", 5900))
    aggregator.add(observation("_ssh._tcp.local.", "Desk", "desk.local.", "10.0.0.2", 22))
    device = aggregator.devices()[0]
    assert device.server == "desk.local."
    assert device.addresses == {"10.0.0.2"}
    assert set(device.services) == {
        ("_rfb._tcp.local.", "Desk"),
        ("_ssh._tcp.local.", "Desk"),
    }


def test_update_replaces_service_and_remove_drops_empty_device():
    aggregator = DeviceAggregator()
    aggregator.add(observation("_rfb._tcp.local.", "Desk", "desk.local.", "10.0.0.2", 5900))
    aggregator.add(observation("_rfb._tcp.local.", "Desk", "desk.local.", "10.0.0.3", 5900))
    assert aggregator.devices()[0].addresses == {"10.0.0.3"}
    aggregator.remove("_rfb._tcp.local.", "Desk")
    assert aggregator.devices() == ()


def test_does_not_merge_similar_display_names_with_different_servers():
    aggregator = DeviceAggregator()
    aggregator.add(observation("_rfb._tcp.local.", "MacBook", "one.local.", "10.0.0.2", 5900))
    aggregator.add(observation("_rfb._tcp.local.", "MacBook", "two.local.", "10.0.0.3", 5900))
    assert len(aggregator.devices()) == 2


def test_retarget_retires_only_the_previous_owner():
    aggregator = DeviceAggregator()
    aggregator.add(
        observation("_rfb._tcp.local.", "MacBook", "old.local.", "10.0.0.2", 5900)
    )
    aggregator.add(
        observation(
            "_rfb._tcp.local.",
            "MacBook",
            "parallel.local.",
            "10.0.0.3",
            5900,
        )
    )

    aggregator.replace(
        observation("_rfb._tcp.local.", "MacBook", "new.local.", "10.0.0.4", 5900),
        previous_server="old.local.",
    )

    assert [device.server for device in aggregator.devices()] == [
        "new.local.",
        "parallel.local.",
    ]


def test_remove_owner_preserves_parallel_same_identity_announcement():
    aggregator = DeviceAggregator()
    aggregator.add(
        observation("_rfb._tcp.local.", "MacBook", "one.local.", "10.0.0.2", 5900)
    )
    aggregator.add(
        observation("_rfb._tcp.local.", "MacBook", "two.local.", "10.0.0.3", 5900)
    )

    aggregator.remove("_rfb._tcp.local.", "MacBook", server="one.local.")

    assert [device.server for device in aggregator.devices()] == ["two.local."]


def test_remove_without_owner_explicitly_drops_all_same_identity_announcements():
    aggregator = DeviceAggregator()
    aggregator.add(
        observation("_rfb._tcp.local.", "MacBook", "one.local.", "10.0.0.2", 5900)
    )
    aggregator.add(
        observation("_rfb._tcp.local.", "MacBook", "two.local.", "10.0.0.3", 5900)
    )

    aggregator.remove("_rfb._tcp.local.", "MacBook")

    assert aggregator.devices() == ()


def test_devices_are_sorted_by_canonical_server_name():
    aggregator = DeviceAggregator()
    aggregator.add(observation("_ssh._tcp.local.", "Zulu", "zulu.local.", "10.0.0.3", 22))
    aggregator.add(observation("_ssh._tcp.local.", "Alpha", "alpha.local.", "10.0.0.2", 22))

    assert [device.server for device in aggregator.devices()] == [
        "alpha.local.",
        "zulu.local.",
    ]
