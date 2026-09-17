"""
Command line interface for pii-masker-ai.
Supports prompt masking, unmasking, and CI scanning for PII leaks.
"""

import argparse
import json
import os
import sys

from pii_masker import __version__
from pii_masker.core import PIIMasker


def cmd_mask(args: argparse.Namespace) -> int:
    text = ""
    if args.file:
        if not os.path.exists(args.file):
            print(f"Error: File not found: {args.file}", file=sys.stderr)
            return 1
        with open(args.file, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    elif args.text:
        text = args.text
    else:
        text = sys.stdin.read()

    masker = PIIMasker()
    result = masker.mask(text, reversible=not args.redact)

    if args.json:
        payload = {
            "masked_text": result.masked_text,
            "mapping": result.mapping,
            "entities_count": len(result.entities),
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(result.masked_text)

    if args.save_mapping and result.mapping:
        with open(args.save_mapping, "w", encoding="utf-8") as f:
            json.dump(result.mapping, f, ensure_ascii=False, indent=2)

    return 0


def cmd_unmask(args: argparse.Namespace) -> int:
    text = ""
    if args.file:
        if not os.path.exists(args.file):
            print(f"Error: Text file not found: {args.file}", file=sys.stderr)
            return 1
        with open(args.file, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    elif args.text:
        text = args.text
    else:
        text = sys.stdin.read()

    if not os.path.exists(args.mapping):
        print(f"Error: Mapping JSON file not found: {args.mapping}", file=sys.stderr)
        return 1

    with open(args.mapping, "r", encoding="utf-8") as f:
        mapping = json.load(f)

    restored = PIIMasker.unmask(text, mapping)
    print(restored)
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """Scan files or directories for PII leaks (returns 1 if PII found, CI-friendly)."""
    masker = PIIMasker()
    target = args.path

    if os.path.isfile(target):
        files_to_scan = [target]
    elif os.path.isdir(target):
        files_to_scan = []
        for root, dirs, files in os.walk(target):
            if ".git" in dirs:
                dirs.remove(".git")
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext in [".txt", ".md", ".json", ".csv", ".log", ".yaml", ".yml", ".py", ".js", ".ts"]:
                    files_to_scan.append(os.path.join(root, f))
    else:
        print(f"Error: Invalid path: {target}", file=sys.stderr)
        return 1

    total_pii = 0
    for file_path in files_to_scan:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            res = masker.mask(content)
            if res.has_pii:
                total_pii += len(res.entities)
                print(f"[PII LEAK] {file_path}: Found {len(res.entities)} item(s):")
                for e in res.entities:
                    print(f"  - [{e.category}] '{e.original[:30]}' (Line char {e.start}-{e.end})")
        except Exception:
            pass

    if total_pii > 0:
        print(f"\nScan completed: {total_pii} PII item(s) detected.", file=sys.stderr)
        return 1 if args.strict else 0
    else:
        print(f"Scan clean: {len(files_to_scan)} file(s) inspected, no PII found. [OK]")
        return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="pii-masker",
        description="Fast, zero-dependency PII masker & redactor for AI prompts and agent memory."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # mask
    p_mask = subparsers.add_parser("mask", help="Mask or redact PII from text or file")
    p_mask.add_argument("text", nargs="?", help="Text string to mask")
    p_mask.add_argument("-f", "--file", help="Input file path to mask")
    p_mask.add_argument("--redact", action="store_true", help="Permanently redact with [TYPE] instead of <TYPE_N>")
    p_mask.add_argument("--json", action="store_true", help="Output result as JSON with mapping")
    p_mask.add_argument("--save-mapping", help="Save unmasking map to a JSON file")
    p_mask.set_defaults(func=cmd_mask)

    # unmask
    p_unmask = subparsers.add_parser("unmask", help="Restore original PII data using a saved mapping")
    p_unmask.add_argument("text", nargs="?", help="Masked text string to restore")
    p_unmask.add_argument("-f", "--file", help="Input masked file path")
    p_unmask.add_argument("-m", "--mapping", required=True, help="Path to JSON mapping file")
    p_unmask.set_defaults(func=cmd_unmask)

    # scan
    p_scan = subparsers.add_parser("scan", help="Scan files or directories for PII leaks")
    p_scan.add_argument("path", default=".", nargs="?", help="File or directory path to scan")
    p_scan.add_argument("--strict", action="store_true", help="Exit with code 1 if any PII is detected")
    p_scan.set_defaults(func=cmd_scan)

    args = parser.parse_args(argv)
    if not args.subcommand:
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
