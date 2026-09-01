# Bonjour Apple Fingerprint CLI Design

## Purpose

Build a macOS command-line tool that passively observes Bonjour/mDNS traffic and produces evidence-backed Apple device classifications. The first version prioritizes Mac, iPhone, iPad, Apple TV, and HomePod devices. It must distinguish explicit model evidence from inference and must not invent a precise hardware model when the network records do not expose one.

## Scope

The CLI listens on the local link for a bounded duration and collects Apple-relevant DNS-SD records. It aggregates records into device views and reports addresses, Bonjour names, hostnames, services, ports, TXT properties, device-category candidates, model candidates, confidence, evidence, and missing signals.

The initial service set is:

- `_rfb._tcp`
- `_device-info._tcp`
- `_airplay._tcp`
- `_raop._tcp`
- `_companion-link._tcp`
- `_smb._tcp`
- `_ssh._tcp`
- `_sleep-proxy._udp`

The first version is passive. It does not scan address ranges, probe TCP or UDP ports, authenticate to devices, or attempt to exploit services.

## Command-Line Interface

The primary command is:

```bash
bonjour-fingerprint scan --duration 10
```

Supported output modes:

- Human-readable summary followed by per-device evidence.
- Structured JSON through `--json`.
- Optional interface selection through `--interface` when supported reliably by the discovery backend.

Normal interruption with `Ctrl+C` stops discovery and renders all records collected so far.

## Identification Semantics

The program separates category classification from exact model identification.

- `high`: An explicit, sanitized device field provides a known model identifier, such as `am=Mac17,9`, and the identifier maps to a known Apple model.
- `medium`: Multiple independent signals agree on a category, such as `_rfb._tcp`, an Apple-specific service combination, and a Bonjour name containing `MacBook Pro`.
- `low`: A single weak signal suggests a category, such as an uncorroborated device name.

An `_rfb._tcp` service on port 5900 can support a Mac or Apple Screen Sharing classification but cannot, by itself, establish an exact Mac hardware identifier. When exact model evidence is absent, the output must use `unknown` and describe the missing evidence.

Conflicting explicit model fields are retained as separate candidates. The tool reports the conflict and lowers confidence instead of selecting one silently.

## Architecture

### Discovery

`discovery.py` uses `python-zeroconf` to browse the configured service types and collect PTR, SRV, TXT, A, and AAAA information. Discovery emits normalized service observations without making classification decisions.

### Domain Models

`models.py` defines typed representations for:

- Service observations
- Network addresses
- Aggregated devices
- Evidence items
- Model candidates
- Classification results

These structures form the stable boundary between discovery, aggregation, identification, and output.

### Aggregation

`aggregator.py` merges observations primarily by canonical DNS-SD target hostname, while preserving all IP addresses and interfaces. It handles duplicate announcements, record updates, removals, IPv4/IPv6 coexistence, and hosts advertising multiple services. It must not merge records solely because display names are similar.

### Fingerprinting

`fingerprints.py` applies deterministic, explainable rules. Rule precedence is:

1. Explicit Apple model identifiers in trusted field names such as `am` or `model`.
2. Explicit product-family fields such as `md`.
3. Consistent combinations of Apple-related service types and conventional ports.
4. Sanitized instance and hostname tokens as weak supporting evidence.

Every conclusion carries evidence references. Model mappings live in `data/apple_models.json` so that new identifiers can be added without changing discovery code.

### Presentation

`cli.py` parses arguments, controls the observation window, handles interruption, and selects human-readable or JSON rendering. Rendering code consumes classification results and does not perform additional inference.

## Data Flow

```text
Bonjour/mDNS packets
  -> normalized service observations
  -> hostname/address/service aggregation
  -> deterministic Apple fingerprint rules
  -> classification with evidence and confidence
  -> text or JSON output
```

## Security and Privacy

All DNS-SD data is untrusted input.

- TXT keys and values are length-limited.
- Control characters and unsafe terminal sequences are removed from display values.
- No discovered value is executed, interpolated into a shell command, or treated as a local path.
- JSON retains normalized evidence rather than raw packet bytes in the first version.
- Passive observation is limited to the local link and the user-selected duration.

The README will state that device names and service records can contain personal information and should not be shared without review.

## Error Handling

- Failure to initialize mDNS discovery produces a nonzero exit with an actionable message.
- An explicitly requested but unavailable interface produces an immediate error.
- Partial records remain visible and are marked incomplete.
- No devices found is a successful empty result that reports the duration and interface context.
- Conflicting model evidence is represented explicitly.
- `Ctrl+C` renders partial results and exits cleanly.

## Testing

### Unit Tests

- TXT normalization and terminal-safety filtering
- Hostname and address aggregation
- Duplicate and updated service observations
- Explicit Apple model mapping
- Category-only inference from service combinations
- Confidence calculation
- Conflicting model evidence

### Fixture Tests

Fixtures represent:

- A Mac with an explicit `am` model identifier
- A MacBook that advertises `_rfb._tcp` but no exact model
- An iPhone with Apple service combinations
- Apple TV and HomePod records with product fields
- A non-Apple device using generic Bonjour services
- Malformed and adversarial TXT values

### Local Integration Test

On the current development Mac, the tool should associate the `_rfb._tcp` instance `MacBook Pro Plus Max Ultra` with `10.147.17.140:5900`, classify it as a probable MacBook Pro, and leave the exact model unknown because Bonjour does not expose `Mac17,9` for that service record.

## Project Layout

```text
bonjour-apple-fingerprint/
├── pyproject.toml
├── README.md
├── data/
│   └── apple_models.json
├── src/
│   └── bonjour_fingerprint/
│       ├── __init__.py
│       ├── aggregator.py
│       ├── cli.py
│       ├── discovery.py
│       ├── fingerprints.py
│       └── models.py
├── tests/
│   ├── fixtures/
│   ├── test_aggregator.py
│   ├── test_cli.py
│   └── test_fingerprints.py
└── docs/
    └── superpowers/specs/
```

## Explicit Non-Goals for Version 1

- Active VNC, SMB, SSH, AFP, or SNMP probing
- BLE or Apple Continuity fingerprinting
- Packet capture in monitor mode
- Machine-learning classification
- Persistent device tracking or historical database
- Web interface
- Claims of exact hardware identity without explicit evidence

## Acceptance Criteria

1. A user can run one command on macOS and receive Apple-focused Bonjour observations after a bounded interval.
2. Observations from multiple service types are grouped without losing address or interface provenance.
3. Every classification includes confidence and concrete evidence.
4. Exact model output requires an explicit recognized model identifier.
5. JSON output is stable and machine-readable.
6. Fixture tests cover positive, unknown, conflicting, and malicious input cases.
7. The current `10.147.17.140` fixture is classified as probable MacBook Pro with exact model `unknown`.
