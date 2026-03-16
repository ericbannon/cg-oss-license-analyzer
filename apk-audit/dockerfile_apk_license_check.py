#!/usr/bin/env python3
"""
dockerfile_apk_license_check.py

Parse apk add commands from a Dockerfile, match those package names against a
repo-package-license-details CSV produced by apk_repo_license_analyzer.py,
print a build-specific package/license report, optionally write CSV/JSON, and
optionally fail on disallowed licenses.

This version deduplicates matches by package so you do not get one row for
every historical version in the repo index.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import shlex
import sys
from collections import defaultdict
from pathlib import Path
from typing import Iterable, List, Dict, Any


APK_CMD_RE = re.compile(r"(^|\s)apk\s+add(\s|$)")


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def join_line_continuations(text: str) -> str:
    return re.sub(r"\\\s*\n", " ", text)


def strip_shell_comments(line: str) -> str:
    out = []
    in_single = False
    in_double = False

    for ch in line:
        if ch == "'" and not in_double:
            in_single = not in_single
            out.append(ch)
        elif ch == '"' and not in_single:
            in_double = not in_double
            out.append(ch)
        elif ch == "#" and not in_single and not in_double:
            break
        else:
            out.append(ch)

    return "".join(out).strip()


def normalize_run_segments(text: str) -> List[str]:
    text = join_line_continuations(text)
    segments: List[str] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line[:3].upper() == "RUN" and (len(line) == 3 or line[3].isspace()):
            shell = strip_shell_comments(line[3:].strip())
            if shell:
                segments.append(shell)

    return segments


def split_shell_chain(cmd: str) -> List[str]:
    parts = []
    buf = []
    in_single = False
    in_double = False
    i = 0

    while i < len(cmd):
        ch = cmd[i]
        nxt = cmd[i:i + 2]

        if ch == "'" and not in_double:
            in_single = not in_single
            buf.append(ch)
            i += 1
            continue

        if ch == '"' and not in_single:
            in_double = not in_double
            buf.append(ch)
            i += 1
            continue

        if not in_single and not in_double and nxt in {"&&", "||"}:
            part = "".join(buf).strip()
            if part:
                parts.append(part)
            buf = []
            i += 2
            continue

        if not in_single and not in_double and ch == ";":
            part = "".join(buf).strip()
            if part:
                parts.append(part)
            buf = []
            i += 1
            continue

        buf.append(ch)
        i += 1

    part = "".join(buf).strip()
    if part:
        parts.append(part)

    return parts


def parse_apk_add_segment(segment: str) -> List[str]:
    if not APK_CMD_RE.search(segment):
        return []

    try:
        tokens = shlex.split(segment, posix=True)
    except ValueError:
        return []

    packages: List[str] = []
    i = 0

    while i < len(tokens):
        if tokens[i] == "apk" and i + 1 < len(tokens) and tokens[i + 1] == "add":
            i += 2
            while i < len(tokens):
                tok = tokens[i]

                if tok in {"&&", "||", ";"}:
                    break

                if tok.startswith("-"):
                    if tok in {
                        "--repository",
                        "--repositories-file",
                        "--root",
                        "--keys-dir",
                        "--arch",
                        "--virtual",
                        "-X",
                        "-p",
                        "-t",
                    }:
                        if i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
                            i += 2
                            continue
                    i += 1
                    continue

                if "$" in tok or "`" in tok:
                    i += 1
                    continue

                name = re.split(r"[<>=~]", tok, maxsplit=1)[0].strip()
                if name and re.match(r"^[A-Za-z0-9._+-]+$", name):
                    packages.append(name)

                i += 1
            break
        i += 1

    return packages


def extract_apk_packages_from_dockerfile(dockerfile: Path) -> List[str]:
    text = read_text(dockerfile)
    packages: List[str] = []

    for run_cmd in normalize_run_segments(text):
        for seg in split_shell_chain(run_cmd):
            packages.extend(parse_apk_add_segment(seg))

    seen = set()
    ordered = []
    for pkg in packages:
        if pkg not in seen:
            seen.add(pkg)
            ordered.append(pkg)

    return ordered


def load_repo_details(csv_path: Path) -> List[Dict[str, str]]:
    with csv_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        fieldnames = reader.fieldnames or []

    required = {"package", "license"}
    missing = required - set(fieldnames)
    if missing:
        raise SystemExit(
            f"repo details CSV is missing required columns: {', '.join(sorted(missing))}"
        )

    return rows


def match_packages(
    packages: Iterable[str],
    repo_rows: List[Dict[str, str]],
    repo_filter: str | None = None,
    arch_filter: str | None = None,
) -> tuple[List[Dict[str, Any]], List[str]]:
    by_pkg: Dict[str, List[Dict[str, str]]] = defaultdict(list)

    for row in repo_rows:
        pkg = (row.get("package") or "").strip()
        if not pkg:
            continue
        if repo_filter and (row.get("repo_base") or "").strip() != repo_filter:
            continue
        if arch_filter and (row.get("arch") or "").strip() != arch_filter:
            continue
        by_pkg[pkg].append(row)

    matches: List[Dict[str, Any]] = []
    unmatched: List[str] = []

    for pkg in packages:
        rows = by_pkg.get(pkg, [])
        if not rows:
            unmatched.append(pkg)
            continue

        for row in rows:
            matches.append(
                {
                    "package": pkg,
                    "license": (row.get("license") or "").strip(),
                    "version": (row.get("version") or "").strip(),
                    "repo_base": (row.get("repo_base") or "").strip(),
                    "arch": (row.get("arch") or "").strip(),
                    "origin": (row.get("origin") or "").strip(),
                }
            )

    matches.sort(
        key=lambda r: (
            r["package"],
            r["repo_base"],
            r["arch"],
            r["version"],
            r["license"],
        )
    )
    return matches, unmatched


def collapse_matches_by_package(matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_pkg: Dict[str, Dict[str, set[str]]] = defaultdict(
        lambda: {
            "versions": set(),
            "licenses": set(),
            "repo_bases": set(),
            "archs": set(),
            "origins": set(),
        }
    )

    for row in matches:
        pkg = row.get("package", "")
        by_pkg[pkg]["versions"].add(row.get("version", ""))
        by_pkg[pkg]["licenses"].add(row.get("license", ""))
        by_pkg[pkg]["repo_bases"].add(row.get("repo_base", ""))
        by_pkg[pkg]["archs"].add(row.get("arch", ""))
        by_pkg[pkg]["origins"].add(row.get("origin", ""))

    collapsed: List[Dict[str, Any]] = []
    for pkg in sorted(by_pkg.keys()):
        vals = by_pkg[pkg]
        versions = sorted(v for v in vals["versions"] if v)
        licenses = sorted(v for v in vals["licenses"] if v)
        repo_bases = sorted(v for v in vals["repo_bases"] if v)
        archs = sorted(v for v in vals["archs"] if v)
        origins = sorted(v for v in vals["origins"] if v)

        collapsed.append(
            {
                "package": pkg,
                "versions": ", ".join(versions),
                "license": " | ".join(licenses),
                "repo_base": ", ".join(repo_bases),
                "arch": ", ".join(archs),
                "origin": ", ".join(origins),
            }
        )

    return collapsed


def compile_license_filters(
    exacts: List[str], regexes: List[str]
) -> tuple[set[str], List[re.Pattern[str]]]:
    compiled = []
    for rx in regexes:
        try:
            compiled.append(re.compile(rx))
        except re.error as exc:
            raise SystemExit(f"invalid --fail-on-license-regex '{rx}': {exc}") from exc
    return set(exacts), compiled


def find_disallowed(
    collapsed_matches: List[Dict[str, Any]],
    exacts: set[str],
    regexes: List[re.Pattern[str]],
) -> List[Dict[str, Any]]:
    disallowed = []

    for row in collapsed_matches:
        license_field = row.get("license", "")
        license_parts = [part.strip() for part in license_field.split("|") if part.strip()]

        matched_parts = []
        for lic in license_parts:
            if lic in exacts or any(rx.search(lic) for rx in regexes):
                matched_parts.append(lic)

        if matched_parts:
            disallowed.append(
                {
                    "package": row["package"],
                    "license": " | ".join(matched_parts),
                    "versions": row["versions"],
                    "repo_base": row["repo_base"],
                    "arch": row["arch"],
                    "origin": row["origin"],
                }
            )

    return disallowed


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    fieldnames = ["package", "versions", "license", "repo_base", "arch", "origin"]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def format_table(rows: List[Dict[str, Any]]) -> str:
    headers = ["package", "versions", "license", "repo_base", "arch"]
    widths = {h: len(h) for h in headers}

    for row in rows:
        for h in headers:
            widths[h] = max(widths[h], len(str(row.get(h, ""))))

    def fmt(row: Dict[str, Any]) -> str:
        return "  ".join(str(row.get(h, "")).ljust(widths[h]) for h in headers)

    lines = [fmt({h: h for h in headers})]
    lines.append("  ".join("-" * widths[h] for h in headers))
    for row in rows:
        lines.append(fmt(row))

    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Extract apk add packages from a Dockerfile and match them to "
            "licenses from repo-package-license-details.csv."
        )
    )
    parser.add_argument("--dockerfile", required=True, help="Path to Dockerfile to inspect.")
    parser.add_argument(
        "--repo-details-csv",
        required=True,
        help="CSV from apk_repo_license_analyzer.py (detail output).",
    )
    parser.add_argument("--repo-base", help="Optional exact repo_base filter.")
    parser.add_argument("--arch", help="Optional exact arch filter, e.g. x86_64.")
    parser.add_argument("--output-csv", help="Write matched package/license rows to CSV.")
    parser.add_argument("--output-json", help="Write full report JSON.")
    parser.add_argument(
        "--fail-on-license",
        action="append",
        default=[],
        help="Fail if an exact license expression matches.",
    )
    parser.add_argument(
        "--fail-on-license-regex",
        action="append",
        default=[],
        help="Fail if a license expression matches this regex.",
    )
    parser.add_argument(
        "--allow-missing-packages",
        action="store_true",
        help="Do not fail if some apk add packages cannot be matched.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()

    dockerfile = Path(args.dockerfile)
    repo_csv = Path(args.repo_details_csv)

    packages = extract_apk_packages_from_dockerfile(dockerfile)
    repo_rows = load_repo_details(repo_csv)
    raw_matches, unmatched = match_packages(
        packages,
        repo_rows,
        repo_filter=args.repo_base,
        arch_filter=args.arch,
    )
    collapsed_matches = collapse_matches_by_package(raw_matches)

    unique_licenses = sorted(
        {
            license_part.strip()
            for row in collapsed_matches
            for license_part in row.get("license", "").split("|")
            if license_part.strip()
        }
    )

    exacts, regexes = compile_license_filters(
        args.fail_on_license,
        args.fail_on_license_regex,
    )
    disallowed = find_disallowed(collapsed_matches, exacts, regexes)

    print("Detected APK packages from Dockerfile:")
    if packages:
        for pkg in packages:
            print(f"  - {pkg}")
    else:
        print("  (none found)")

    print()
    print("Matched package licenses:")
    if collapsed_matches:
        print(format_table(collapsed_matches))
    else:
        print("  (no matches found)")

    print()
    print("Unique licenses in this build step:")
    if unique_licenses:
        for lic in unique_licenses:
            print(f"  - {lic}")
    else:
        print("  (none)")

    if unmatched:
        print()
        print("Packages not found in repo details CSV:")
        for pkg in unmatched:
            print(f"  - {pkg}")

    if disallowed:
        print()
        print("Disallowed licenses found:")
        for row in disallowed:
            print(f"  - {row['package']}: {row['license']}")

    payload = {
        "dockerfile": str(dockerfile),
        "repo_details_csv": str(repo_csv),
        "repo_base_filter": args.repo_base,
        "arch_filter": args.arch,
        "packages": packages,
        "matched_rows": collapsed_matches,
        "unmatched_packages": unmatched,
        "unique_licenses": unique_licenses,
        "disallowed_rows": disallowed,
        "policy_result": "fail" if disallowed or (unmatched and not args.allow_missing_packages) else "pass",
    }

    if args.output_csv:
        write_csv(Path(args.output_csv), collapsed_matches)

    if args.output_json:
        write_json(Path(args.output_json), payload)

    if disallowed:
        return 2
    if unmatched and not args.allow_missing_packages:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())