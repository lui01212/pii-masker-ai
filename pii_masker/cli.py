"""
Command line interface for pii-masker-ai.
Supports prompt masking, unmasking, CI scanning for PII leaks, and dataset batch sanitization.
"""

import argparse
import csv
import io
import json
import os
import re
import sys
from typing import Any, Callable, Dict, List, Optional, Set

from pii_masker import __version__
from pii_masker.core import PIIMasker, MaskMode, _MappingState

_PEM_BEGIN_REGEX = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_PEM_END_REGEX = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")


def _load_allowlist(allowlist_arg: Optional[str]) -> Set[str]:
    """Parse comma-separated values or file path into a set of exempted tokens."""
    if not allowlist_arg:
        return set()
    if os.path.isfile(allowlist_arg):
        with open(allowlist_arg, "r", encoding="utf-8") as f:
            return {line.strip() for line in f if line.strip() and not line.startswith("#")}
    return {item.strip() for item in allowlist_arg.split(",") if item.strip()}


def _write_mapping(path: str, mapping: Dict[str, str]) -> None:
    """Write the unmasking map readable by its owner only: it holds the original values."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.chmod(path, 0o600)  # an existing file keeps its old permissions otherwise
    except OSError:
        pass
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(mapping, f, ensure_ascii=False, indent=2)


def _same_file(path_a: str, path_b: str) -> bool:
    if os.path.exists(path_b):
        try:
            return os.path.samefile(path_a, path_b)
        except OSError:
            pass
    return os.path.normcase(os.path.abspath(path_a)) == os.path.normcase(os.path.abspath(path_b))


def _mask_json_value(value: Any, mask_str: Callable[[str], str]) -> Any:
    """Mask every string in nested JSON; a number is replaced only if it looks like PII."""
    if isinstance(value, str):
        return mask_str(value)
    if isinstance(value, dict):
        return {key: _mask_json_value(item, mask_str) for key, item in value.items()}
    if isinstance(value, list):
        return [_mask_json_value(item, mask_str) for item in value]
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        text = str(value)
        masked = mask_str(text)
        return masked if masked != text else value
    return value


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

    # Determine mode
    mode = MaskMode.REVERSIBLE
    if getattr(args, "redact", False):
        mode = MaskMode.REDACT
    elif getattr(args, "mode", None):
        mode = args.mode.lower()

    allowlist = _load_allowlist(getattr(args, "allowlist", None))
    masker = PIIMasker(allowlist=list(allowlist), salt=getattr(args, "salt", None))
    result = masker.mask(text, mode=mode)

    if args.json:
        payload = {
            "masked_text": result.masked_text,
            "mapping": result.mapping,
            "entities_count": len(result.entities),
            "mode": mode,
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(result.masked_text)

    if args.save_mapping:
        # Always written, so a mapping from an earlier run is never left behind
        _write_mapping(args.save_mapping, result.mapping)

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

    try:
        with open(args.mapping, "r", encoding="utf-8") as f:
            mapping = json.load(f)
    except (OSError, ValueError) as exc:
        print(f"Error: Cannot read mapping JSON file {args.mapping}: {exc}", file=sys.stderr)
        return 1
    if not isinstance(mapping, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in mapping.items()
    ):
        print(
            f"Error: Mapping file {args.mapping} must be a JSON object of placeholder -> original strings.",
            file=sys.stderr,
        )
        return 1

    restored = PIIMasker.unmask(text, mapping)
    print(restored)
    return 0


def cmd_batch(args: argparse.Namespace) -> int:
    """Batch sanitize dataset files (.jsonl, .csv, .txt) with zero dependencies."""
    input_path = args.input
    if not os.path.exists(input_path):
        print(f"Error: Input file not found: {input_path}", file=sys.stderr)
        return 1
    if args.output and _same_file(input_path, args.output):
        print("Error: Output file must differ from the input file (it would be truncated).", file=sys.stderr)
        return 1

    # Detect format
    fmt = (args.format or "").lower()
    if not fmt:
        ext = os.path.splitext(input_path)[1].lower()
        if ext == ".jsonl":
            fmt = "jsonl"
        elif ext == ".csv":
            fmt = "csv"
        else:
            fmt = "txt"

    mode = (args.mode or MaskMode.REVERSIBLE).lower()
    allowlist = _load_allowlist(args.allowlist)
    masker = PIIMasker(allowlist=list(allowlist), salt=getattr(args, "salt", None))

    fields = [f.strip() for f in args.fields.split(",")] if args.fields else None
    # One mapping for the whole run: tokens continue across records and never collide
    state = _MappingState()
    total_processed = 0
    invalid_lines: List[int] = []

    def mask_str(text: str) -> str:
        return masker._mask(text, True, mode, None, state).masked_text

    if fmt == "csv":
        with open(input_path, "r", encoding="utf-8", errors="replace", newline="") as in_f:
            header = next(csv.reader(in_f), None)
        if not header:
            print("Error: Empty or invalid CSV file.", file=sys.stderr)
            return 1
        missing = [f for f in fields or [] if f not in header]
        if missing:
            print(
                f"Error: Unknown CSV column(s): {', '.join(missing)}. "
                f"Available columns: {', '.join(header)}",
                file=sys.stderr,
            )
            return 1

    out_file = open(args.output, "w", encoding="utf-8", newline="") if args.output else sys.stdout

    try:
        if fmt == "jsonl":
            with open(input_path, "r", encoding="utf-8", errors="replace") as in_f:
                for line_no, line in enumerate(in_f, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        # Never copied to the output: it may hold unmasked PII
                        invalid_lines.append(line_no)
                        print(f"Error: line {line_no}: invalid JSON, record skipped", file=sys.stderr)
                        continue
                    if isinstance(obj, dict) and fields:
                        for k in fields:
                            if k in obj:
                                obj[k] = _mask_json_value(obj[k], mask_str)
                    else:
                        obj = _mask_json_value(obj, mask_str)
                    out_file.write(json.dumps(obj, ensure_ascii=False) + "\n")
                    total_processed += 1

        elif fmt == "csv":
            with open(input_path, "r", encoding="utf-8", errors="replace", newline="") as in_f:
                reader = csv.reader(in_f)
                header = next(reader)
                writer = csv.writer(out_file)
                writer.writerow(header)

                selected = {i for i, name in enumerate(header) if not fields or name in fields}
                for row in reader:
                    if not row:
                        continue
                    row = row + [""] * (len(header) - len(row))
                    for i, cell in enumerate(row):
                        # Cells beyond the header have no column name and are always masked
                        if cell and (i in selected or i >= len(header)):
                            row[i] = mask_str(cell)
                    writer.writerow(row)
                    total_processed += 1

        else:  # plain text
            with open(input_path, "r", encoding="utf-8", errors="replace") as in_f:
                pem_lines: List[str] = []
                for line in in_f:
                    if pem_lines:
                        pem_lines.append(line)
                        if _PEM_END_REGEX.search(line):
                            out_file.write(mask_str("".join(pem_lines)))
                            total_processed += len(pem_lines)
                            pem_lines = []
                        continue
                    begin = _PEM_BEGIN_REGEX.search(line)
                    if begin and not _PEM_END_REGEX.search(line, begin.end()):
                        # A multi-line private key is buffered up to its END line and masked as one block
                        pem_lines.append(line)
                        continue
                    out_file.write(mask_str(line))
                    total_processed += 1
                if pem_lines:
                    out_file.write(mask_str("".join(pem_lines)))
                    total_processed += len(pem_lines)

    finally:
        if args.output:
            out_file.close()

    if args.save_mapping:
        _write_mapping(args.save_mapping, state.mapping)

    if args.output:
        print(f"Batch sanitized {total_processed} record(s) -> {args.output} (mode={mode})")

    if invalid_lines:
        print(f"Error: {len(invalid_lines)} invalid JSON line(s) were skipped.", file=sys.stderr)
        return 1
    return 0


def _preview(value: str) -> str:
    """A non-secret hint of a detected value: its first 4 characters and its length."""
    return f"'{value[:4]}...' ({len(value)} chars)"


def _is_binary(path: str) -> bool:
    with open(path, "rb") as f:
        return b"\0" in f.read(8192)


def cmd_scan(args: argparse.Namespace) -> int:
    """Scan files or directories for PII leaks (returns 1 if PII found, CI-friendly)."""
    masker = PIIMasker()
    target = args.path

    def report_walk_error(exc: OSError) -> None:
        print(f"Warning: Cannot read {exc.filename}: {exc.strerror}", file=sys.stderr)

    if os.path.isfile(target):
        files_to_scan = [target]
    elif os.path.isdir(target):
        files_to_scan = []
        for root, dirs, files in os.walk(target, onerror=report_walk_error):
            if ".git" in dirs:
                dirs.remove(".git")
            for f in files:
                files_to_scan.append(os.path.join(root, f))
    else:
        print(f"Error: Invalid path: {target}", file=sys.stderr)
        return 1

    total_pii = 0
    scanned = 0
    for file_path in files_to_scan:
        try:
            if _is_binary(file_path):
                continue
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except OSError as exc:
            print(f"Warning: Cannot read {file_path}: {exc}", file=sys.stderr)
            continue
        scanned += 1
        res = masker.mask(content, mode=MaskMode.REDACT)
        if res.has_pii:
            total_pii += len(res.entities)
            print(f"[PII LEAK] {file_path}: Found {len(res.entities)} item(s):")
            for e in res.entities:
                line_no = content.count("\n", 0, e.start) + 1
                # Never print the detected value itself: scan output often ends up in CI logs
                print(f"  - [{e.category}] {file_path}:{line_no} {_preview(e.original)}")

    if total_pii > 0:
        print(f"\nScan completed: {total_pii} PII item(s) detected.", file=sys.stderr)
        return 1 if args.strict else 0
    else:
        print(f"Scan clean: {scanned} file(s) inspected, no PII found. [OK]")
        return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="pii-masker",
        description="Fast, zero-dependency PII masker & redactor for AI prompts and agent memory."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")
    salt_help = "Secret salt for --mode hash (default: $PII_MASKER_SALT, else random for this run)"

    # mask
    p_mask = subparsers.add_parser("mask", help="Mask or redact PII from text or file")
    p_mask.add_argument("text", nargs="?", help="Text string to mask")
    p_mask.add_argument("-f", "--file", help="Input file path to mask")
    p_mask.add_argument("--mode", choices=["reversible", "redact", "hash", "synthetic"], default="reversible",
                        help="Masking strategy (default: reversible)")
    p_mask.add_argument("--redact", action="store_true", help="Shortcut for --mode redact")
    p_mask.add_argument("--allowlist", help="Comma-separated string or file path containing tokens to exempt")
    p_mask.add_argument("--salt", help=salt_help)
    p_mask.add_argument("--json", action="store_true", help="Output result as JSON with mapping")
    p_mask.add_argument("--save-mapping", help="Save unmasking map to a JSON file")
    p_mask.set_defaults(func=cmd_mask)

    # unmask
    p_unmask = subparsers.add_parser("unmask", help="Restore original PII data using a saved mapping")
    p_unmask.add_argument("text", nargs="?", help="Masked text string to restore")
    p_unmask.add_argument("-f", "--file", help="Input masked file path")
    p_unmask.add_argument("-m", "--mapping", required=True, help="Path to JSON mapping file")
    p_unmask.set_defaults(func=cmd_unmask)

    # batch
    p_batch = subparsers.add_parser("batch", help="Batch sanitize dataset files (.jsonl, .csv, .txt)")
    p_batch.add_argument("-i", "--input", required=True, help="Input dataset file path")
    p_batch.add_argument("-o", "--output", help="Output sanitized file path (default: stdout)")
    p_batch.add_argument("--format", choices=["jsonl", "csv", "txt"], help="Dataset format (inferred if omitted)")
    p_batch.add_argument("--fields", help="Comma-separated list of JSON/CSV keys to mask")
    p_batch.add_argument("--mode", choices=["reversible", "redact", "hash", "synthetic"], default="reversible",
                         help="Masking mode")
    p_batch.add_argument("--allowlist", help="Comma-separated string or file path containing tokens to exempt")
    p_batch.add_argument("--salt", help=salt_help)
    p_batch.add_argument("--save-mapping", help="Save aggregate unmasking mapping to a JSON file")
    p_batch.set_defaults(func=cmd_batch)

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
