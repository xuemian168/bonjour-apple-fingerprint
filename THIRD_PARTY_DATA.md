# Third-party model data

The generated `src/bonjour_fingerprint/data/apple_models.json` file contains
data derived from the following pinned sources.

## apple_device_identifiers

- Repository: <https://github.com/clo4/apple_device_identifiers>
- Pinned commit: `52b730be317fb64d75dae72ea1edbe5eca946250`
- Input: `ids.json`
- License: Unlicense / public domain
- Bundled license: `src/bonjour_fingerprint/data/licenses/apple-device-identifiers-UNLICENSE.txt`

The upstream project describes the compilation as best effort and notes that
Apple does not publish a complete canonical list.

## AppleDB

- Repository: <https://github.com/littlebyteorg/appledb>
- Pinned generated-data commit: `b69e073a0010d221b446ac3fd9165ab52d1af919`
- Input: `device/main.json` from the repository's `gh-pages` branch
- License: MIT
- Bundled license: `src/bonjour_fingerprint/data/licenses/appledb-MIT.txt`

## Apple Support override

`Mac17,9` is overridden from Apple's
[MacBook Pro identification page](https://support.apple.com/en-us/108052),
checked on 2026-09-08. Apple lists `Mac17,7` and `Mac17,9` for the 14-inch
MacBook Pro with M5 Pro or M5 Max introduced in 2026. This reference is used as
factual verification and is not vendored content.

The machine-readable source pins and verification date are also available in
`src/bonjour_fingerprint/data/apple_models.meta.json`.
