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
            print(
                json.dumps(
                    [result_to_dict(item) for item in results],
                    ensure_ascii=False,
                    indent=2,
                )
            )
        else:
            print(render_text(results, args.duration, args.interface))
        return 0
    except DiscoveryError as error:
        print(f"bonjour-fingerprint: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
