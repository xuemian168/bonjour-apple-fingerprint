import json
from importlib.resources import files

import pytest

from bonjour_fingerprint.catalog import (
    CatalogBuildError,
    CatalogEntry,
    build_catalog,
    load_catalog,
    serialize_catalog,
)
from bonjour_fingerprint.fingerprints import load_model_catalog


def test_bundled_catalog_has_broad_apple_coverage():
    catalog = load_model_catalog()

    assert len(catalog) >= 640
    assert catalog["Mac17,9"].category == "MacBook Pro"
    assert "iPhone 13" in catalog["iPhone14,5"].names
    assert catalog["iPad13,4"].category == "iPad Pro"
    assert catalog["AppleTV11,1"].category == "Apple TV"
    assert catalog["AudioAccessory1,1"].category == "HomePod"
    assert catalog["Watch6,1"].category == "Apple Watch"
    assert catalog["AirPods1,1"].category == "AirPods"
    assert catalog["RealityDevice14,1"].category == "Apple Vision Pro"
    assert all(entry.names and entry.sources for entry in catalog.values())


def test_bundled_metadata_matches_catalog_and_pins_sources():
    catalog = load_model_catalog()
    resource = files("bonjour_fingerprint").joinpath("data/apple_models.meta.json")
    with resource.open("r", encoding="utf-8") as handle:
        metadata = json.load(handle)

    assert metadata["model_count"] == len(catalog)
    assert metadata["checked_at"] == "2026-09-08"
    assert len(metadata["sources"]["apple_device_identifiers"]["commit"]) == 40
    assert len(metadata["sources"]["appledb"]["commit"]) == 40
    assert {
        source for entry in catalog.values() for source in entry.sources
    } <= metadata["sources"].keys()


def test_load_catalog_accepts_legacy_string_mapping(tmp_path):
    path = tmp_path / "legacy.json"
    path.write_text(json.dumps({"Mac17,9": "MacBook Pro"}), encoding="utf-8")

    assert load_catalog(path) == {
        "Mac17,9": CatalogEntry(
            category="MacBook Pro",
            names=("MacBook Pro",),
            sources=("legacy",),
        )
    }


def test_build_catalog_merges_names_and_applies_authoritative_override():
    base = {
        "Mac17,9": ["MacBook Pro (14-inch, M5 Pro)"],
        "iPhone14,5": ["iPhone 13"],
    }
    appledb = [
        {
            "name": "MacBook Pro (14-inch, M5 Pro)",
            "type": "MacBook Pro",
            "identifier": ["Mac17,9"],
        },
        {
            "name": "iPhone 13",
            "type": "iPhone",
            "identifier": ["iPhone14,5"],
        },
    ]
    overrides = {
        "Mac17,9": {
            "category": "MacBook Pro",
            "names": ["MacBook Pro (14-inch, M5 Pro or M5 Max, 2026)"],
            "source": "apple_support_108052",
        }
    }

    catalog = build_catalog(base, appledb, overrides)

    assert catalog["Mac17,9"] == CatalogEntry(
        category="MacBook Pro",
        names=("MacBook Pro (14-inch, M5 Pro or M5 Max, 2026)",),
        sources=("apple_support_108052",),
    )
    assert catalog["iPhone14,5"].sources == (
        "apple_device_identifiers",
        "appledb",
    )


def test_build_catalog_rejects_conflicting_appledb_categories():
    appledb = [
        {"name": "Thing A", "type": "Mac", "identifier": ["Thing1,1"]},
        {"name": "Thing B", "type": "iPhone", "identifier": ["Thing1,1"]},
    ]

    with pytest.raises(CatalogBuildError, match="conflicting categories"):
        build_catalog({}, appledb, {})


def test_catalog_serialization_is_deterministic():
    catalog = {
        "iPhone14,5": CatalogEntry(
            category="iPhone",
            names=("iPhone 13",),
            sources=("appledb",),
        ),
        "Mac17,9": CatalogEntry(
            category="MacBook Pro",
            names=("MacBook Pro",),
            sources=("appledb",),
        ),
    }

    first = serialize_catalog(catalog)
    second = serialize_catalog(dict(reversed(list(catalog.items()))))

    assert first == second
    assert list(json.loads(first)["models"]) == ["Mac17,9", "iPhone14,5"]
