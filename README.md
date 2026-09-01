# Bonjour Apple Fingerprint

Bonjour Apple Fingerprint is a macOS command-line tool that passively observes
Bonjour/mDNS advertisements and reports evidence-backed Apple device
classifications. Discovery is bounded to the selected duration and the local
multicast link. The tool does not scan address ranges, connect to discovered
services, authenticate to devices, or actively probe them.

## Installation

Python 3.11 or newer is required.

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
```

## Usage

Run a ten-second scan with human-readable output:

```bash
.venv/bin/bonjour-fingerprint scan
```

Request structured JSON, choose a duration, or limit discovery to a network
interface:

```bash
.venv/bin/bonjour-fingerprint scan --json
.venv/bin/bonjour-fingerprint scan --duration 5
.venv/bin/bonjour-fingerprint scan --duration 5 --interface en0
```

An abridged result for a Mac that exposes Screen Sharing may look like this:

```text
10.147.17.140
  category: MacBook Pro
  model: unknown
  confidence: medium
  evidence: _rfb._tcp:5900 and instance name "MacBook Pro Plus Max Ultra"
  missing: explicit Apple model identifier
```

The service on port 5900 and the instance name support the category, but they
do not reveal an exact hardware model.

## Evidence and confidence

Category classification and exact model identification are separate:

- **High** confidence requires an explicit recognized model identifier in a
  model TXT field, such as `am=Mac17,9`.
- **Medium** confidence means multiple independent signals agree on a category,
  such as an explicit product-family field corroborated by a conventional
  Bonjour name or relevant service.
- **Low** confidence means only one category signal is available (including a
  lone explicit product-family field), a signal is unrecognized, or explicit
  fields conflict.

Exact model names are reported only when an explicit identifier is present and
recognized by the bundled model catalog. Names, service combinations, ports,
and IP addresses never become exact model identifiers. Without recognized
explicit evidence, `model` remains `unknown`. Bonjour evidence is descriptive,
not proof of ownership or identity.

## Privacy and limitations

Bonjour instance names, hostnames, and TXT records may contain personal
information. Review text and JSON output before storing or sharing it.

- Multicast discovery normally sees only devices on the same local link;
  routers and network isolation can hide records.
- Private or randomized MAC addresses limit hardware identity and tracking;
  this tool does not use a MAC address as an exact-model claim.
- Bonjour names and TXT fields are untrusted and spoofable, even when their
  contents match known Apple values.
- Sleeping, offline, firewalled, or quiet devices may not advertise during the
  observation window.
- Some devices omit `_device-info`, so an exact model may remain unknown.
- The tool performs no BLE discovery and no active VNC, SSH, SMB, or other
  network probing.

## Development

Install the development dependencies and run the test suite:

```bash
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
```
