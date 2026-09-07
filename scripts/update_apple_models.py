#!/usr/bin/env python3
"""Build the bundled Apple model catalog from pinned, redistributable sources."""

import argparse
import json
import sys
import tempfile
import urllib.request
from datetime import date
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bonjour_fingerprint.catalog import build_catalog, serialize_catalog  # noqa: E402


APPLE_IDENTIFIERS_COMMIT = "52b730be317fb64d75dae72ea1edbe5eca946250"
APPLEDB_COMMIT = "b69e073a0010d221b446ac3fd9165ab52d1af919"
APPLE_IDENTIFIERS_URL = (
    "https://raw.githubusercontent.com/clo4/apple_device_identifiers/"
    f"{APPLE_IDENTIFIERS_COMMIT}/ids.json"
)
APPLEDB_URL = (
    "https://raw.githubusercontent.com/littlebyteorg/appledb/"
    f"{APPLEDB_COMMIT}/device/main.json"
)
DATA_DIR = ROOT / "src" / "bonjour_fingerprint" / "data"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apple-identifiers", type=Path)
    parser.add_argument("--appledb", type=Path)
    parser.add_argument("--overrides", type=Path, default=DATA_DIR / "apple_model_overrides.json")
    parser.add_argument("--output", type=Path, default=DATA_DIR / "apple_models.json")
    parser.add_argument("--metadata", type=Path, default=DATA_DIR / "apple_models.meta.json")
    parser.add_argument("--checked-at", default=date.today().isoformat())
    return parser.parse_args(argv)


def read_json(path: Path | None, url: str) -> Any:
    if path is not None:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "bonjour-apple-fingerprint-catalog-updater/1"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def write_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        handle.write(content)
        temporary = Path(handle.name)
    temporary.replace(path)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    base = read_json(args.apple_identifiers, APPLE_IDENTIFIERS_URL)
    appledb = read_json(args.appledb, APPLEDB_URL)
    overrides = read_json(args.overrides, "")
    catalog = build_catalog(base, appledb, overrides)

    metadata = {
        "schema_version": 1,
        "checked_at": args.checked_at,
        "model_count": len(catalog),
        "sources": {
            "apple_device_identifiers": {
                "repository": "https://github.com/clo4/apple_device_identifiers",
                "commit": APPLE_IDENTIFIERS_COMMIT,
                "license": "Unlicense / public domain",
                "artifact": APPLE_IDENTIFIERS_URL,
            },
            "appledb": {
                "repository": "https://github.com/littlebyteorg/appledb",
                "commit": APPLEDB_COMMIT,
                "license": "MIT",
                "artifact": APPLEDB_URL,
            },
            "apple_support_108052": {
                "url": "https://support.apple.com/en-us/108052",
                "publisher": "Apple",
                "checked_at": args.checked_at,
            },
        },
    }
    write_atomic(args.output, serialize_catalog(catalog))
    write_atomic(
        args.metadata,
        json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )
    print(f"wrote {len(catalog)} identifiers to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
