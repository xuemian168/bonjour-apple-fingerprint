import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
SOURCE_ORDER = {
    "apple_device_identifiers": 0,
    "appledb": 1,
}


class CatalogError(ValueError):
    """Raised when a model catalog is malformed."""


class CatalogBuildError(CatalogError):
    """Raised when upstream data cannot be merged safely."""


@dataclass(frozen=True, slots=True)
class CatalogEntry:
    category: str
    names: tuple[str, ...]
    sources: tuple[str, ...]


CatalogValue = str | CatalogEntry


def load_catalog(path: Path | Any) -> dict[str, CatalogEntry]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise CatalogError("catalog root must be an object")

    if "schema_version" not in payload and "models" not in payload:
        catalog = {}
        for identifier, name in payload.items():
            if not isinstance(name, str):
                raise CatalogError(
                    f"legacy catalog entry {identifier!r} must be a string"
                )
            catalog[_identifier(identifier)] = CatalogEntry(
                category=_infer_category(identifier, (name,)),
                names=(_name(name),),
                sources=("legacy",),
            )
        return catalog

    if payload.get("schema_version") != SCHEMA_VERSION:
        raise CatalogError(f"unsupported catalog schema: {payload.get('schema_version')!r}")
    models = payload.get("models")
    if not isinstance(models, dict):
        raise CatalogError("catalog models must be an object")

    catalog: dict[str, CatalogEntry] = {}
    for identifier, raw in models.items():
        if not isinstance(raw, dict):
            raise CatalogError(f"catalog entry {identifier!r} must be an object")
        names = raw.get("names")
        sources = raw.get("sources")
        category = raw.get("category")
        if not isinstance(names, list) or not names:
            raise CatalogError(f"catalog entry {identifier!r} has no names")
        if not isinstance(sources, list) or not sources:
            raise CatalogError(f"catalog entry {identifier!r} has no sources")
        if not isinstance(category, str) or not category.strip():
            raise CatalogError(f"catalog entry {identifier!r} has no category")
        catalog[_identifier(identifier)] = CatalogEntry(
            category=category.strip(),
            names=_sorted_unique(_name(item) for item in names),
            sources=_sorted_sources(_source(item) for item in sources),
        )
    return catalog


def coerce_entry(identifier: str, value: CatalogValue) -> CatalogEntry:
    if isinstance(value, CatalogEntry):
        return value
    if isinstance(value, str):
        name = _name(value)
        return CatalogEntry(
            category=_infer_category(identifier, (name,)),
            names=(name,),
            sources=("legacy",),
        )
    raise CatalogError(f"unsupported catalog value for {identifier!r}")


def build_catalog(
    apple_device_identifiers: Mapping[str, Sequence[str]],
    appledb_devices: Sequence[Mapping[str, Any]],
    overrides: Mapping[str, Mapping[str, Any]],
) -> dict[str, CatalogEntry]:
    names_by_id: dict[str, set[str]] = {}
    sources_by_id: dict[str, set[str]] = {}
    categories_by_id: dict[str, set[str]] = {}
    name_priorities: dict[tuple[str, str], int] = {}

    for raw_identifier, raw_names in apple_device_identifiers.items():
        identifier = _identifier(raw_identifier)
        if isinstance(raw_names, str) or not isinstance(raw_names, Sequence):
            raise CatalogBuildError(f"names for {identifier!r} must be an array")
        names = {_name(item) for item in raw_names}
        if not names:
            raise CatalogBuildError(f"no names for {identifier!r}")
        names_by_id.setdefault(identifier, set()).update(names)
        sources_by_id.setdefault(identifier, set()).add("apple_device_identifiers")
        for name in names:
            name_priorities[(identifier, name)] = 0

    for row in appledb_devices:
        name = _name(row.get("name"))
        category = _normalized_category(row.get("type"), name)
        identifiers = row.get("identifier", ())
        if isinstance(identifiers, str) or not isinstance(identifiers, Sequence):
            raise CatalogBuildError("AppleDB identifier field must be an array")
        for raw_identifier in identifiers:
            identifier = _identifier(raw_identifier)
            names_by_id.setdefault(identifier, set()).add(name)
            sources_by_id.setdefault(identifier, set()).add("appledb")
            categories_by_id.setdefault(identifier, set()).add(category)
            name_priorities[(identifier, name)] = 1

    conflicts = {
        identifier: categories
        for identifier, categories in categories_by_id.items()
        if len(categories) > 1
    }
    if conflicts:
        identifier = sorted(conflicts)[0]
        categories = ", ".join(sorted(conflicts[identifier]))
        raise CatalogBuildError(
            f"conflicting categories for {identifier!r}: {categories}"
        )

    catalog: dict[str, CatalogEntry] = {}
    for identifier in sorted(names_by_id):
        names = _collapse_equivalent_names(
            identifier, names_by_id[identifier], name_priorities
        )
        category = next(iter(categories_by_id.get(identifier, ())), None)
        catalog[identifier] = CatalogEntry(
            category=category or _infer_category(identifier, names),
            names=names,
            sources=_sorted_sources(sources_by_id[identifier]),
        )

    for raw_identifier, override in overrides.items():
        identifier = _identifier(raw_identifier)
        raw_names = override.get("names")
        if isinstance(raw_names, str) or not isinstance(raw_names, Sequence):
            raise CatalogBuildError(f"override names for {identifier!r} must be an array")
        catalog[identifier] = CatalogEntry(
            category=_category(override.get("category")),
            names=_sorted_unique(_name(item) for item in raw_names),
            sources=(_source(override.get("source")),),
        )
    return catalog


def serialize_catalog(catalog: Mapping[str, CatalogEntry]) -> str:
    payload = {
        "schema_version": SCHEMA_VERSION,
        "models": {
            identifier: {
                "category": entry.category,
                "names": list(entry.names),
                "sources": list(entry.sources),
            }
            for identifier, entry in sorted(catalog.items())
        },
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def _identifier(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CatalogBuildError("device identifier must be a non-empty string")
    return value.strip()


def _name(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CatalogBuildError("device name must be a non-empty string")
    return value.strip()


def _source(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CatalogBuildError("source must be a non-empty string")
    return value.strip()


def _category(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CatalogBuildError("device category must be a non-empty string")
    return value.strip()


def _normalized_category(value: Any, name: str) -> str:
    category = _category(value)
    if category == "Headset" and name.casefold().startswith("vision pro"):
        return "Apple Vision Pro"
    return category


def _sorted_unique(values: Any) -> tuple[str, ...]:
    return tuple(sorted(set(values), key=lambda value: (value.casefold(), value)))


def _sorted_sources(values: Any) -> tuple[str, ...]:
    return tuple(
        sorted(
            set(values),
            key=lambda value: (SOURCE_ORDER.get(value, len(SOURCE_ORDER)), value),
        )
    )


def _collapse_equivalent_names(
    identifier: str,
    names: set[str],
    priorities: Mapping[tuple[str, str], int],
) -> tuple[str, ...]:
    groups: dict[tuple[str, ...], list[str]] = {}
    for name in names:
        signature = tuple(sorted(re.findall(r"[a-z0-9]+", name.casefold())))
        groups.setdefault(signature, []).append(name)
    selected = (
        max(
            group,
            key=lambda name: (priorities.get((identifier, name), -1), name),
        )
        for group in groups.values()
    )
    return _sorted_unique(selected)


def _infer_category(identifier: str, names: Sequence[str]) -> str:
    normalized = f"{identifier} {' '.join(names)}".lower()
    for token, category in (
        ("macbook pro", "MacBook Pro"),
        ("macbook air", "MacBook Air"),
        ("macbook", "MacBook"),
        ("mac studio", "Mac Studio"),
        ("mac mini", "Mac mini"),
        ("macmini", "Mac mini"),
        ("mac pro", "Mac Pro"),
        ("imac pro", "iMac Pro"),
        ("imac", "iMac"),
        ("iphone", "iPhone"),
        ("ipad", "iPad"),
        ("apple tv", "Apple TV"),
        ("appletv", "Apple TV"),
        ("homepod", "HomePod"),
        ("audioaccessory", "HomePod"),
        ("apple watch", "Apple Watch"),
        ("watch", "Apple Watch"),
        ("airpods", "AirPods"),
        ("iprod", "AirPods"),
        ("airtag", "AirTag"),
        ("airport", "AirPort"),
        ("ipod", "iPod touch"),
        ("display", "Display"),
    ):
        if token in normalized:
            return category
    return "Apple device"
