# Apple model catalog expansion design

## Goal

Expand the six-entry model mapping into a reproducible, offline, provenance-
bearing catalog covering Apple device families while preserving conservative
Bonjour classification. Exact-model claims still require an explicit `am` or
`model` TXT identifier.

## Data sources

The catalog generator merges immutable, commit-pinned artifacts from the
public-domain `clo4/apple_device_identifiers` project and MIT-licensed AppleDB.
A small local override layer may replace an entry only when it records a named
source. The initial override corrects `Mac17,9` to the range stated on Apple's
MacBook Pro identification page.

The generated metadata records source repository, commit, artifact URL,
license, verification date, and model count. Scanning never accesses the
network; only an explicit maintainer update runs the downloader.

## Catalog and classification

Each identifier maps to a category, one or more marketing names, and source
keys. Superficial punctuation or word-order variants collapse deterministically.
Distinct variants remain separate candidates.

A single candidate retains high confidence. Multiple candidates produce a
category-level model label, medium confidence, a `unique model mapping`
missing-field marker, and the complete candidate list in text and JSON. More
than one observed explicit identifier remains a low-confidence conflict.
Legacy custom JSON mappings from identifier to string remain accepted.

Service names, ports, IP addresses, and combinations of Bonjour services never
select a catalog identifier or exact model.

## Failure handling and tests

The generator rejects malformed input, empty fields, and multiple AppleDB
categories for one identifier. It writes output atomically only after a full
successful build. Stable sorting makes the catalog reproducible for identical
inputs.

Tests cover broad family representation, legacy loading, merge and override
precedence, conflict failure, deterministic serialization, one-to-many
classification, candidate rendering, the existing fixture suite, package
contents, and installed CLI behavior.
