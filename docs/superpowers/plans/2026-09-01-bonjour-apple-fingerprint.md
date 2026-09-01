# Bonjour Apple Fingerprint CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a macOS CLI that passively observes Apple-related Bonjour services and reports evidence-backed device categories and explicit hardware-model identifiers without overstating uncertain results.

**Architecture:** A synchronous discovery adapter converts `python-zeroconf` callbacks into normalized observations, an aggregator groups observations by canonical target hostname, and a deterministic rules engine returns classifications with evidence and confidence. Rendering remains separate from inference so text and JSON outputs contain the same facts.

**Tech Stack:** Python 3.11+, `zeroconf` 0.151.x, `ifaddr` 0.2.x, `pytest` 8.x, standard-library `argparse`, dataclasses, JSON, and importlib resources.

**Spec:** `docs/superpowers/specs/2026-09-01-bonjour-apple-fingerprint-design.md`

## Global Constraints

- Support macOS with Python 3.11 or newer.
- Discovery is passive and local-link only; do not add TCP/UDP port probes, authentication, or packet injection.
- Exact model output requires an explicit recognized model identifier such as `am=Mac17,9`.
- Treat every discovered DNS-SD name and TXT value as untrusted input; strip terminal controls and cap displayed strings at 512 characters.
- Keep discovery, aggregation, classification, and rendering in separate modules with the interfaces defined below.
- Human-readable and JSON output must be derived from the same `ClassificationResult` objects.

## File Map

- `pyproject.toml`: package metadata, runtime dependencies, test configuration, and console entry point.
- `src/bonjour_fingerprint/__init__.py`: package version export.
- `src/bonjour_fingerprint/models.py`: normalized observation, device, evidence, candidate, and result types.
- `src/bonjour_fingerprint/sanitize.py`: bounded terminal-safe conversion of untrusted Bonjour strings.
- `src/bonjour_fingerprint/aggregator.py`: deterministic hostname-based observation aggregation.
- `src/bonjour_fingerprint/fingerprints.py`: Apple model catalog loading and explainable classification rules.
- `src/bonjour_fingerprint/discovery.py`: `python-zeroconf` adapter and interface resolution.
- `src/bonjour_fingerprint/render.py`: text and JSON-compatible result rendering.
- `src/bonjour_fingerprint/cli.py`: argument parsing, discovery lifecycle, and exit codes.
- `src/bonjour_fingerprint/data/apple_models.json`: explicit Apple model identifier mapping used by the rules engine.
- `tests/fixtures/*.json`: realistic, sanitized Bonjour observation samples.
- `tests/test_models.py`: data normalization and sanitization tests.
- `tests/test_aggregator.py`: grouping, deduplication, update, and removal tests.
- `tests/test_fingerprints.py`: exact-model, category-only, weak-signal, and conflict tests.
- `tests/test_discovery.py`: mocked zeroconf callback and interface-resolution tests.
- `tests/test_cli.py`: command parsing, text/JSON output, empty results, interruption, and errors.
- `README.md`: installation, usage, privacy warning, evidence semantics, and limitations.

---

### Task 1: Package Foundation and Trusted Domain Boundary

**Files:**
- Create: `pyproject.toml`
- Create: `README.md`
- Create: `src/bonjour_fingerprint/__init__.py`
- Create: `src/bonjour_fingerprint/models.py`
- Create: `src/bonjour_fingerprint/sanitize.py`
- Create: `tests/test_models.py`

**Interfaces:**
- Produces: `sanitize_text(value: str | bytes, limit: int = 512) -> str`
- Produces: `Confidence`, `ServiceObservation`, `DeviceRecord`, `Evidence`, `ModelCandidate`, and `ClassificationResult`
- `ServiceObservation.identity` returns `tuple[str, str]` of `(service_type, instance_name)`.

- [ ] **Step 1: Add packaging and a failing sanitization/model test**

Create `pyproject.toml` with:

```toml
[build-system]
requires = ["hatchling>=1.27,<2"]
build-backend = "hatchling.build"

[project]
name = "bonjour-apple-fingerprint"
version = "0.1.0"
description = "Evidence-backed Apple device identification from Bonjour/mDNS"
readme = "README.md"
requires-python = ">=3.11"
dependencies = [
  "ifaddr>=0.2.0,<0.3",
  "zeroconf>=0.151.0,<0.152",
]

[project.optional-dependencies]
dev = ["pytest>=8.0,<9"]

[project.scripts]
bonjour-fingerprint = "bonjour_fingerprint.cli:main"

[tool.hatch.build.targets.wheel]
packages = ["src/bonjour_fingerprint"]

[tool.pytest.ini_options]
addopts = "-q"
testpaths = ["tests"]
```

Create an initial `README.md` so editable packaging can resolve the declared readme before Task 6 expands it:

```markdown
# Bonjour Apple Fingerprint

Passive, evidence-backed Apple device identification from Bonjour/mDNS.
```

Create `tests/test_models.py` with:

```python
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
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/pytest tests/test_models.py -v
```

Expected: collection fails because `bonjour_fingerprint.models` does not exist.

- [ ] **Step 3: Implement sanitization and domain types**

Create `src/bonjour_fingerprint/sanitize.py`:

```python
import re

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def sanitize_text(value: str | bytes, limit: int = 512) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return _CONTROL.sub("", value)[:limit]
```

Create `src/bonjour_fingerprint/models.py` with these exact public types:

```python
from dataclasses import dataclass, field
from enum import StrEnum

from .sanitize import sanitize_text


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True, slots=True)
class ServiceObservation:
    service_type: str
    instance_name: str
    server: str
    port: int
    addresses: tuple[str, ...] = ()
    properties: dict[str, str] = field(default_factory=dict)
    interface: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "service_type", sanitize_text(self.service_type))
        object.__setattr__(self, "instance_name", sanitize_text(self.instance_name))
        object.__setattr__(self, "server", sanitize_text(self.server).lower())
        object.__setattr__(self, "addresses", tuple(dict.fromkeys(self.addresses)))
        object.__setattr__(
            self,
            "properties",
            {sanitize_text(k).lower(): sanitize_text(v) for k, v in self.properties.items()},
        )

    @property
    def identity(self) -> tuple[str, str]:
        return self.service_type, self.instance_name


@dataclass(slots=True)
class DeviceRecord:
    server: str
    addresses: set[str] = field(default_factory=set)
    interfaces: set[str] = field(default_factory=set)
    services: dict[tuple[str, str], ServiceObservation] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Evidence:
    source: str
    value: str
    strength: Confidence


@dataclass(frozen=True, slots=True)
class ModelCandidate:
    identifier: str
    name: str
    source: str


@dataclass(frozen=True, slots=True)
class ClassificationResult:
    device: DeviceRecord
    category: str
    model: str
    confidence: Confidence
    evidence: tuple[Evidence, ...]
    candidates: tuple[ModelCandidate, ...] = ()
    missing: tuple[str, ...] = ()
    conflicts: tuple[str, ...] = ()
```

Create `src/bonjour_fingerprint/__init__.py`:

```python
__version__ = "0.1.0"
```

- [ ] **Step 4: Run the focused tests and full empty-suite check**

Run:

```bash
.venv/bin/pytest tests/test_models.py -v
.venv/bin/pytest
```

Expected: both commands pass.

- [ ] **Step 5: Commit the package boundary**

```bash
git add pyproject.toml README.md src/bonjour_fingerprint tests/test_models.py
git commit -m "feat: define normalized Bonjour domain models"
```

---

### Task 2: Deterministic Device Aggregation

**Files:**
- Create: `src/bonjour_fingerprint/aggregator.py`
- Create: `tests/test_aggregator.py`

**Interfaces:**
- Consumes: `ServiceObservation` and `DeviceRecord` from Task 1.
- Produces: `DeviceAggregator.add(observation)`, `remove(service_type, instance_name)`, and `devices()`.
- `DeviceAggregator.devices() -> tuple[DeviceRecord, ...]` is sorted by canonical server name.

- [ ] **Step 1: Write failing aggregation tests**

Create `tests/test_aggregator.py`:

```python
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
```

- [ ] **Step 2: Run aggregation tests and verify failure**

Run: `.venv/bin/pytest tests/test_aggregator.py -v`

Expected: import failure for `bonjour_fingerprint.aggregator`.

- [ ] **Step 3: Implement aggregation with a reverse service index**

Create `src/bonjour_fingerprint/aggregator.py`:

```python
from .models import DeviceRecord, ServiceObservation


class DeviceAggregator:
    def __init__(self) -> None:
        self._devices: dict[str, DeviceRecord] = {}
        self._owners: dict[tuple[str, str], str] = {}

    def add(self, observation: ServiceObservation) -> None:
        identity = observation.identity
        previous_server = self._owners.get(identity)
        if previous_server is not None:
            previous = self._devices[previous_server]
            previous.services.pop(identity, None)
            self._rebuild(previous_server)
        device = self._devices.setdefault(
            observation.server, DeviceRecord(server=observation.server)
        )
        device.services[identity] = observation
        self._owners[identity] = observation.server
        self._rebuild(observation.server)

    def remove(self, service_type: str, instance_name: str) -> None:
        identity = service_type, instance_name
        server = self._owners.pop(identity, None)
        if server is None:
            return
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
```

- [ ] **Step 4: Verify aggregation behavior**

Run: `.venv/bin/pytest tests/test_aggregator.py -v`

Expected: 3 tests pass.

- [ ] **Step 5: Commit aggregation**

```bash
git add src/bonjour_fingerprint/aggregator.py tests/test_aggregator.py
git commit -m "feat: aggregate Bonjour services by target host"
```

---

### Task 3: Explainable Apple Fingerprint Rules

**Files:**
- Create: `src/bonjour_fingerprint/fingerprints.py`
- Create: `src/bonjour_fingerprint/data/apple_models.json`
- Create: `tests/test_fingerprints.py`

**Interfaces:**
- Consumes: `DeviceRecord`, `Evidence`, `ModelCandidate`, `ClassificationResult`, and `Confidence`.
- Produces: `load_model_catalog(path: Path | None = None) -> dict[str, str]`.
- Produces: `classify(device: DeviceRecord, catalog: Mapping[str, str]) -> ClassificationResult`.

- [ ] **Step 1: Write failing exact, inferred, and conflicting-model tests**

Create `tests/test_fingerprints.py` with helpers that build `DeviceRecord` through `DeviceAggregator`, then assert:

```python
from bonjour_fingerprint.aggregator import DeviceAggregator
from bonjour_fingerprint.fingerprints import classify
from bonjour_fingerprint.models import Confidence, ServiceObservation


CATALOG = {"Mac17,9": "MacBook Pro (14-inch, M5 Pro, 2026)"}


def device_with(*observations):
    aggregator = DeviceAggregator()
    for item in observations:
        aggregator.add(item)
    return aggregator.devices()[0]


def service(kind, name="Desk", properties=None, port=0):
    return ServiceObservation(
        kind, name, "desk.local.", port, ("10.0.0.2",), properties or {}, "en0"
    )


def test_explicit_known_apple_identifier_is_high_confidence():
    result = classify(
        device_with(service("_device-info._tcp.local.", properties={"am": "Mac17,9"})),
        CATALOG,
    )
    assert result.model == "MacBook Pro (14-inch, M5 Pro, 2026)"
    assert result.confidence is Confidence.HIGH


def test_rfb_and_macbook_name_classify_category_but_not_exact_model():
    result = classify(
        device_with(service("_rfb._tcp.local.", name="MacBook Pro Plus Max Ultra", port=5900)),
        CATALOG,
    )
    assert result.category == "MacBook Pro"
    assert result.model == "unknown"
    assert result.confidence is Confidence.MEDIUM
    assert "explicit Apple model identifier" in result.missing


def test_conflicting_explicit_identifiers_are_not_silently_resolved():
    device = device_with(
        service("_device-info._tcp.local.", name="One", properties={"am": "Mac17,9"}),
        service("_airplay._tcp.local.", name="Two", properties={"am": "Mac99,1"}),
    )
    result = classify(device, {**CATALOG, "Mac99,1": "Imaginary Mac"})
    assert result.model == "unknown"
    assert result.conflicts == ("Mac17,9", "Mac99,1")
```

- [ ] **Step 2: Verify fingerprint tests fail**

Run: `.venv/bin/pytest tests/test_fingerprints.py -v`

Expected: import failure for `bonjour_fingerprint.fingerprints`.

- [ ] **Step 3: Add a minimal catalog and deterministic rule engine**

Create `src/bonjour_fingerprint/data/apple_models.json`:

```json
{
  "Mac17,9": "MacBook Pro (14-inch, M5 Pro, 2026)",
  "MacBookPro18,3": "MacBook Pro (14-inch, 2021)",
  "Mac14,7": "MacBook Pro (13-inch, M2, 2022)",
  "iPhone14,5": "iPhone 13",
  "AudioAccessory1,1": "HomePod"
}
```

Implement `src/bonjour_fingerprint/fingerprints.py` with:

```python
import json
from collections.abc import Mapping
from importlib.resources import files
from pathlib import Path

from .models import (
    ClassificationResult,
    Confidence,
    DeviceRecord,
    Evidence,
    ModelCandidate,
)

MODEL_KEYS = ("am", "model")


def load_model_catalog(path: Path | None = None) -> dict[str, str]:
    resource = path or files("bonjour_fingerprint").joinpath("data/apple_models.json")
    with resource.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def classify(device: DeviceRecord, catalog: Mapping[str, str]) -> ClassificationResult:
    evidence: list[Evidence] = []
    identifiers: dict[str, str] = {}
    names = " ".join(service.instance_name.lower() for service in device.services.values())
    service_types = {service.service_type for service in device.services.values()}

    for service in device.services.values():
        for key in MODEL_KEYS:
            identifier = service.properties.get(key)
            if identifier in catalog:
                identifiers[identifier] = f"{service.service_type} TXT {key}"
                evidence.append(Evidence(identifiers[identifier], identifier, Confidence.HIGH))

    if len(identifiers) > 1:
        return ClassificationResult(
            device, _category(names, service_types), "unknown", Confidence.LOW,
            tuple(evidence), conflicts=tuple(sorted(identifiers))
        )
    if len(identifiers) == 1:
        identifier, source = next(iter(identifiers.items()))
        candidate = ModelCandidate(identifier, catalog[identifier], source)
        return ClassificationResult(
            device, _category(names, service_types), candidate.name, Confidence.HIGH,
            tuple(evidence), candidates=(candidate,)
        )

    category = _category(names, service_types)
    if "_rfb._tcp.local." in service_types:
        evidence.append(Evidence("service", "_rfb._tcp on port 5900", Confidence.MEDIUM))
    if "macbook pro" in names:
        evidence.append(Evidence("instance name", "MacBook Pro", Confidence.MEDIUM))
    confidence = Confidence.MEDIUM if len(evidence) >= 2 else Confidence.LOW
    return ClassificationResult(
        device, category, "unknown", confidence, tuple(evidence),
        missing=("explicit Apple model identifier",)
    )


def _category(names: str, service_types: set[str]) -> str:
    if "macbook pro" in names:
        return "MacBook Pro"
    if "iphone" in names:
        return "iPhone"
    if "homepod" in names or "_raop._tcp.local." in service_types:
        return "Apple audio device"
    if "_rfb._tcp.local." in service_types:
        return "Mac"
    return "Apple device candidate"
```

Update `pyproject.toml` to include package data:

```toml
[tool.hatch.build.targets.wheel.force-include]
"src/bonjour_fingerprint/data/apple_models.json" = "bonjour_fingerprint/data/apple_models.json"
```

- [ ] **Step 4: Run fingerprint and full tests**

Run:

```bash
.venv/bin/pytest tests/test_fingerprints.py -v
.venv/bin/pytest
```

Expected: all tests pass.

- [ ] **Step 5: Commit the rule engine and catalog**

```bash
git add pyproject.toml src/bonjour_fingerprint/data src/bonjour_fingerprint/fingerprints.py tests/test_fingerprints.py
git commit -m "feat: classify Apple Bonjour evidence"
```

---

### Task 4: Bonjour Discovery Adapter

**Files:**
- Create: `src/bonjour_fingerprint/discovery.py`
- Create: `tests/test_discovery.py`

**Interfaces:**
- Consumes: `ServiceObservation` and `DeviceAggregator`.
- Produces: `APPLE_SERVICE_TYPES: tuple[str, ...]`.
- Produces: `resolve_interface_addresses(name: str) -> list[str]`.
- Produces: `discover(duration: float, service_types: tuple[str, ...] = APPLE_SERVICE_TYPES, interface: str | None = None) -> tuple[DeviceRecord, ...]`.
- Raises: `DiscoveryError` for invalid duration, unknown interface, and zeroconf initialization failures.

- [ ] **Step 1: Write failing adapter tests using fake ServiceInfo**

Create `tests/test_discovery.py` covering:

```python
from bonjour_fingerprint.discovery import ObservationListener


class FakeInfo:
    server = "Desk.local."
    port = 5900
    properties = {b"model": b"MacBookPro"}

    def parsed_scoped_addresses(self):
        return ["10.0.0.2", "fe80::1%en0"]


class FakeZeroconf:
    def get_service_info(self, service_type, name, timeout=3000):
        return FakeInfo()


def test_listener_converts_service_info_to_normalized_observation():
    listener = ObservationListener(interface="en0")
    listener.add_service(FakeZeroconf(), "_rfb._tcp.local.", "Desk._rfb._tcp.local.")
    device = listener.devices()[0]
    service = next(iter(device.services.values()))
    assert service.instance_name == "Desk"
    assert service.properties == {"model": "MacBookPro"}
    assert service.addresses == ("10.0.0.2", "fe80::1%en0")
```

Add a test that monkeypatches `ifaddr.get_adapters()` with one adapter named `en0`, asserts its IPv4 address is returned, and asserts an unknown interface raises `DiscoveryError`.

- [ ] **Step 2: Verify discovery tests fail**

Run: `.venv/bin/pytest tests/test_discovery.py -v`

Expected: import failure for `bonjour_fingerprint.discovery`.

- [ ] **Step 3: Implement service browsing and lifecycle cleanup**

Implement `src/bonjour_fingerprint/discovery.py` around these public members:

```python
import time
from contextlib import suppress

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


class DiscoveryError(RuntimeError):
    pass


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
        info = zc.get_service_info(service_type, name, timeout=3000)
        if info is None or not info.server:
            return
        properties = {key: value for key, value in info.properties.items()}
        self._aggregator.add(ServiceObservation(
            service_type=service_type,
            instance_name=_instance_name(name, service_type),
            server=info.server,
            port=info.port,
            addresses=tuple(info.parsed_scoped_addresses()),
            properties=properties,
            interface=self._interface,
        ))


def _instance_name(name: str, service_type: str) -> str:
    suffix = "." + service_type
    return name[:-len(suffix)] if name.endswith(suffix) else name
```

Complete `resolve_interface_addresses` by iterating `ifaddr.get_adapters()`, matching `adapter.nice_name` or `adapter.name`, and returning non-link-local IPv4 strings. Complete `discover` by validating `duration > 0`, resolving an optional interface to addresses, constructing `Zeroconf(interfaces=addresses or None)`, starting one `ServiceBrowser` for all `APPLE_SERVICE_TYPES`, waiting in intervals no longer than 0.1 seconds, and closing browser and zeroconf objects in `finally`. Convert constructor and browsing exceptions to `DiscoveryError` while allowing `KeyboardInterrupt` to return the listener's current devices.

- [ ] **Step 4: Run mocked discovery tests and a five-second local smoke test**

Run:

```bash
.venv/bin/pytest tests/test_discovery.py -v
.venv/bin/python -c 'from bonjour_fingerprint.discovery import discover; print([(d.server, sorted(d.addresses)) for d in discover(5)])'
```

Expected: tests pass; smoke test exits within six seconds and prints a Python list without traceback.

- [ ] **Step 5: Commit discovery**

```bash
git add src/bonjour_fingerprint/discovery.py tests/test_discovery.py
git commit -m "feat: observe Apple Bonjour services"
```

---

### Task 5: Shared Rendering and CLI Lifecycle

**Files:**
- Create: `src/bonjour_fingerprint/render.py`
- Create: `src/bonjour_fingerprint/cli.py`
- Create: `tests/test_cli.py`

**Interfaces:**
- Consumes: `discover`, `load_model_catalog`, `classify`, and `ClassificationResult`.
- Produces: `result_to_dict(result: ClassificationResult) -> dict[str, object]`.
- Produces: `render_text(results: Sequence[ClassificationResult], duration: float, interface: str | None) -> str`.
- Produces: `main(argv: Sequence[str] | None = None) -> int`.

- [ ] **Step 1: Write failing CLI tests for text, JSON, empty, and error paths**

Create `tests/test_cli.py` using `monkeypatch` and `capsys`. Build a MacBook result through the real aggregator and classifier, then cover:

```python
import json

from bonjour_fingerprint import cli


def test_json_output_is_machine_readable(monkeypatch, capsys, macbook_device):
    monkeypatch.setattr(cli, "discover", lambda duration, interface=None: (macbook_device,))
    assert cli.main(["scan", "--duration", "1", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["category"] == "MacBook Pro"
    assert payload[0]["model"] == "unknown"
    assert payload[0]["addresses"] == ["10.147.17.140"]


def test_empty_result_is_successful(monkeypatch, capsys):
    monkeypatch.setattr(cli, "discover", lambda duration, interface=None: ())
    assert cli.main(["scan", "--duration", "0.1"]) == 0
    assert "No Apple Bonjour devices observed" in capsys.readouterr().out


def test_discovery_error_returns_exit_two(monkeypatch, capsys):
    def fail(duration, interface=None):
        raise cli.DiscoveryError("interface en9 not found")
    monkeypatch.setattr(cli, "discover", fail)
    assert cli.main(["scan", "--interface", "en9"]) == 2
    assert "interface en9 not found" in capsys.readouterr().err
```

Also assert text output lists confidence, each evidence item, missing signals, and conflicts.

- [ ] **Step 2: Verify CLI tests fail**

Run: `.venv/bin/pytest tests/test_cli.py -v`

Expected: import failure for `bonjour_fingerprint.cli`.

- [ ] **Step 3: Implement rendering from shared result objects**

In `src/bonjour_fingerprint/render.py`, implement `result_to_dict` with stable keys:

```python
def result_to_dict(result):
    return {
        "server": result.device.server,
        "addresses": sorted(result.device.addresses),
        "interfaces": sorted(result.device.interfaces),
        "category": result.category,
        "model": result.model,
        "confidence": result.confidence.value,
        "services": [
            {
                "type": service.service_type,
                "name": service.instance_name,
                "port": service.port,
                "properties": dict(sorted(service.properties.items())),
            }
            for service in sorted(
                result.device.services.values(),
                key=lambda item: (item.service_type, item.instance_name),
            )
        ],
        "evidence": [
            {"source": item.source, "value": item.value, "strength": item.strength.value}
            for item in result.evidence
        ],
        "candidates": [
            {"identifier": item.identifier, "name": item.name, "source": item.source}
            for item in result.candidates
        ],
        "missing": list(result.missing),
        "conflicts": list(result.conflicts),
    }
```

Implement `render_text` as deterministic newline-joined output with one device block and indented services/evidence. For an empty sequence return `No Apple Bonjour devices observed in {duration:g}s{interface_suffix}.`.

Use this implementation shape:

```python
from collections.abc import Sequence

from .models import ClassificationResult


def render_text(
    results: Sequence[ClassificationResult], duration: float, interface: str | None
) -> str:
    suffix = f" on {interface}" if interface else ""
    if not results:
        return f"No Apple Bonjour devices observed in {duration:g}s{suffix}."
    lines: list[str] = []
    for result in results:
        addresses = ", ".join(sorted(result.device.addresses)) or "unknown"
        lines.extend([
            f"{addresses} ({result.device.server})",
            f"  category: {result.category}",
            f"  model: {result.model}",
            f"  confidence: {result.confidence.value}",
            "  services:",
        ])
        for service in sorted(
            result.device.services.values(),
            key=lambda item: (item.service_type, item.instance_name),
        ):
            lines.append(f"    - {service.service_type} {service.instance_name} :{service.port}")
        lines.append("  evidence:")
        lines.extend(
            f"    - [{item.strength.value}] {item.source}: {item.value}"
            for item in result.evidence
        )
        if result.missing:
            lines.append("  missing: " + ", ".join(result.missing))
        if result.conflicts:
            lines.append("  conflicts: " + ", ".join(result.conflicts))
    return "\n".join(lines)
```

- [ ] **Step 4: Implement argument parsing and error codes**

In `src/bonjour_fingerprint/cli.py`, create an `argparse` parser with required `scan` subcommand, `--duration` float default `10.0`, `--interface`, and `--json`. `main` calls `discover`, classifies every device with one loaded catalog, sorts results by server, prints JSON with `ensure_ascii=False, indent=2` or `render_text`, returns `0` on success, and catches `DiscoveryError` to print `bonjour-fingerprint: {error}` to stderr and return `2`.

The command lifecycle is:

```python
import argparse
import json
import sys
from collections.abc import Sequence

from .discovery import DiscoveryError, discover
from .fingerprints import classify, load_model_catalog
from .render import render_text, result_to_dict


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bonjour-fingerprint")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan")
    scan.add_argument("--duration", type=float, default=10.0)
    scan.add_argument("--interface")
    scan.add_argument("--json", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        devices = discover(args.duration, interface=args.interface)
        catalog = load_model_catalog()
        results = [classify(device, catalog) for device in devices]
        results.sort(key=lambda item: item.device.server)
        if args.json:
            print(json.dumps([result_to_dict(item) for item in results], ensure_ascii=False, indent=2))
        else:
            print(render_text(results, args.duration, args.interface))
        return 0
    except DiscoveryError as error:
        print(f"bonjour-fingerprint: {error}", file=sys.stderr)
        return 2
```

Use this executable footer:

```python
if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 5: Run CLI tests and verify installed entry point**

Run:

```bash
.venv/bin/pytest tests/test_cli.py -v
.venv/bin/bonjour-fingerprint --help
.venv/bin/bonjour-fingerprint scan --duration 3 --json
```

Expected: tests pass; help lists `scan`; the live command prints a valid JSON array and exits normally.

- [ ] **Step 6: Commit rendering and CLI**

```bash
git add src/bonjour_fingerprint/render.py src/bonjour_fingerprint/cli.py tests/test_cli.py
git commit -m "feat: add evidence-backed Bonjour CLI output"
```

---

### Task 6: Realistic Fixtures, Documentation, and Release Verification

**Files:**
- Create: `tests/fixtures/macbook_rfb_only.json`
- Create: `tests/fixtures/mac_explicit_model.json`
- Create: `tests/fixtures/apple_devices.json`
- Create: `tests/fixtures/adversarial_txt.json`
- Modify: `tests/test_fingerprints.py`
- Modify: `README.md`

**Interfaces:**
- Consumes all public interfaces from Tasks 1–5.
- Produces documented user contract and regression fixtures for Apple-specific evidence semantics.

- [ ] **Step 1: Add failing fixture regression tests**

Add a parametrized test that reads each JSON fixture, constructs `ServiceObservation` objects, aggregates and classifies them, and compares `category`, `model`, and `confidence` to the fixture's `expected` object. The `macbook_rfb_only.json` fixture must contain:

```json
{
  "observations": [
    {
      "service_type": "_rfb._tcp.local.",
      "instance_name": "MacBook Pro Plus Max Ultra",
      "server": "MacBook-Pro-Plus-Max-Ultra.local.",
      "port": 5900,
      "addresses": ["10.147.17.140"],
      "properties": {},
      "interface": "en0"
    }
  ],
  "expected": {
    "category": "MacBook Pro",
    "model": "unknown",
    "confidence": "medium"
  }
}
```

The explicit-model fixture must use `_device-info._tcp.local.` with `am=Mac17,9`. The adversarial fixture must include escape characters represented with JSON unicode escapes and verify the rendered output contains no control characters.

- [ ] **Step 2: Run fixture tests and verify at least one initial failure**

Run: `.venv/bin/pytest tests/test_fingerprints.py -v`

Expected: failure until fixture-loading helpers and any missing category rules are complete.

- [ ] **Step 3: Complete fixture coverage without weakening evidence rules**

Add only deterministic category rules needed by the fixtures. Do not convert service combinations into exact model identifiers. Ensure iPhone, Apple TV, and HomePod fixtures use explicit product-family TXT values or multiple corroborating service/name signals.

- [ ] **Step 4: Write the README user contract**

Create `README.md` containing:

- Project purpose and passive/local-link scope.
- Python 3.11+ installation using `python3 -m venv .venv` and `.venv/bin/pip install -e .`.
- Commands for text, JSON, duration, and interface selection.
- A sample `10.147.17.140` result that says `MacBook Pro`, `model: unknown`, and cites `_rfb._tcp:5900`.
- Confidence definitions and the rule that exact models require explicit recognized identifiers.
- A privacy warning that Bonjour names and TXT records may contain personal information.
- Limitations: same-link multicast visibility, private MAC addresses, spoofable TXT fields, sleeping devices, missing `_device-info`, and no BLE/VNC active probing.
- Development commands: `.venv/bin/pip install -e '.[dev]'` and `.venv/bin/pytest`.

- [ ] **Step 5: Run final automated and live verification**

Run:

```bash
.venv/bin/pytest -v
.venv/bin/python -m compileall -q src tests
.venv/bin/bonjour-fingerprint scan --duration 5
.venv/bin/bonjour-fingerprint scan --duration 5 --json | .venv/bin/python -m json.tool >/dev/null
git status --short
```

Expected:

- All tests pass.
- Compileall exits zero.
- Text scan completes without traceback.
- JSON scan parses successfully.
- The target fixture and any live `10.147.17.140` observation never claim `Mac17,9` unless an explicit model TXT field is present.
- Git status shows only intended README, fixture, and test changes before commit.

- [ ] **Step 6: Commit documentation and release verification assets**

```bash
git add README.md tests/fixtures tests/test_fingerprints.py
git commit -m "docs: document Bonjour evidence and limitations"
```

- [ ] **Step 7: Record the clean final state**

Run:

```bash
git status --short
git log --oneline --max-count=8
```

Expected: status is empty and the log contains the design, plan, and six implementation commits.
