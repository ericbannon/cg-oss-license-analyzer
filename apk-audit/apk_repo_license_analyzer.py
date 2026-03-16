#!/usr/bin/env python3
"""
Analyze Chainguard/Wolfi APK repositories by reading APKINDEX.tar.gz files
and extracting declared OSS licenses from package metadata.

Supports two modes:
1) Full repository inventory from one or more repo base URLs.
2) Package-filtered inventory using package names captured from builds.

Examples:
  python apk_repo_license_analyzer.py \
    --repo-list repos.txt \
    --arches x86_64,aarch64 \
    --summary-csv repo-license-summary.csv \
    --details-csv repo-package-license-details.csv \
    --unique-licenses-file unique-licenses.txt

  python apk_repo_license_analyzer.py \
    --repo-list repos.txt \
    --arches x86_64 \
    --package-list packages.txt \
    --details-csv filtered-details.csv
"""
from __future__ import annotations

import argparse
import base64
import csv
import io
import json
import os
import sys
import tarfile
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

DEFAULT_TIMEOUT = 45
DEFAULT_USER_AGENT = "apk-repo-license-analyzer/1.0"


@dataclass
class PackageRecord:
    repo_base: str
    arch: str
    package: str
    version: str
    license: str
    origin: str = ""
    url: str = ""
    description: str = ""
    maintainer: str = ""


@dataclass
class RepoSummary:
    repo_base: str
    arch: str
    package_count: int
    licensed_package_count: int
    unlicensed_package_count: int
    unique_license_count: int
    licenses: List[str]
    status: str
    error: str = ""


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def normalize_repo_base(url: str) -> str:
    url = url.strip()
    if not url:
        return url
    return url.rstrip("/")


def read_nonempty_lines(path: str) -> List[str]:
    items: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            items.append(line)
    return items


def build_auth_header() -> Optional[str]:
    # Chainguard docs use HTTP_AUTH=basic:apk.cgr.dev:user:<token>
    http_auth = os.environ.get("HTTP_AUTH", "").strip()
    if http_auth.startswith("basic:"):
        parts = http_auth.split(":", 4)
        if len(parts) == 5:
            _, _host, username, password = parts[1:]
            token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
            return f"Basic {token}"

    # Generic fallback for environments that prefer separate vars.
    username = os.environ.get("APK_REPO_USERNAME")
    password = os.environ.get("APK_REPO_PASSWORD")
    if username and password:
        token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        return f"Basic {token}"

    return None


def download_bytes(url: str, timeout: int = DEFAULT_TIMEOUT) -> bytes:
    headers = {"User-Agent": DEFAULT_USER_AGENT}
    auth_header = build_auth_header()
    if auth_header:
        headers["Authorization"] = auth_header
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def repo_index_url(repo_base: str, arch: str) -> str:
    repo_base = normalize_repo_base(repo_base)
    parsed = urllib.parse.urlparse(repo_base)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"Unsupported repo URL: {repo_base}")

    # Accept either repo root or arch-specific URL.
    path = parsed.path.rstrip("/")
    if path.endswith(f"/{arch}"):
        return repo_base.rstrip("/") + "/APKINDEX.tar.gz"
    return repo_base.rstrip("/") + f"/{arch}/APKINDEX.tar.gz"


def extract_apkindex_text(index_bytes: bytes) -> str:
    bio = io.BytesIO(index_bytes)
    with tarfile.open(fileobj=bio, mode="r:gz") as tf:
        try:
            member = tf.getmember("APKINDEX")
        except KeyError as exc:
            raise ValueError("APKINDEX file not found in archive") from exc
        extracted = tf.extractfile(member)
        if extracted is None:
            raise ValueError("Failed to extract APKINDEX from archive")
        return extracted.read().decode("utf-8", errors="replace")


def parse_apkindex_record(block: str, repo_base: str, arch: str) -> Optional[PackageRecord]:
    fields: Dict[str, List[str]] = defaultdict(list)
    for line in block.splitlines():
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        fields[key].append(value)

    package = fields.get("P", [""])[0].strip()
    version = fields.get("V", [""])[0].strip()
    if not package or not version:
        return None

    return PackageRecord(
        repo_base=repo_base,
        arch=arch,
        package=package,
        version=version,
        license=fields.get("L", [""])[0].strip(),
        origin=fields.get("o", [""])[0].strip(),
        url=fields.get("U", [""])[0].strip(),
        description=fields.get("T", [""])[0].strip(),
        maintainer=fields.get("m", [""])[0].strip(),
    )


def parse_apkindex_text(text: str, repo_base: str, arch: str) -> List[PackageRecord]:
    records: List[PackageRecord] = []
    for block in text.strip().split("\n\n"):
        record = parse_apkindex_record(block, repo_base=repo_base, arch=arch)
        if record is not None:
            records.append(record)
    return records


def filter_packages(records: Iterable[PackageRecord], package_allowlist: Optional[Set[str]]) -> List[PackageRecord]:
    if not package_allowlist:
        return list(records)
    return [record for record in records if record.package in package_allowlist or record.origin in package_allowlist]


def summarize_records(records: List[PackageRecord], repo_base: str, arch: str, status: str = "ok", error: str = "") -> RepoSummary:
    licenses = sorted({record.license for record in records if record.license})
    package_count = len(records)
    licensed_count = sum(1 for record in records if record.license)
    return RepoSummary(
        repo_base=repo_base,
        arch=arch,
        package_count=package_count,
        licensed_package_count=licensed_count,
        unlicensed_package_count=package_count - licensed_count,
        unique_license_count=len(licenses),
        licenses=licenses,
        status=status,
        error=error,
    )


def write_csv(path: str, fieldnames: Sequence[str], rows: Iterable[Dict[str, object]]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def print_summary_table(summaries: Sequence[RepoSummary]) -> None:
    headers = [
        "repo_base",
        "arch",
        "package_count",
        "licensed_package_count",
        "unlicensed_package_count",
        "unique_license_count",
        "licenses",
        "status",
    ]
    rows = []
    for s in summaries:
        rows.append([
            s.repo_base,
            s.arch,
            str(s.package_count),
            str(s.licensed_package_count),
            str(s.unlicensed_package_count),
            str(s.unique_license_count),
            ", ".join(s.licenses),
            s.status,
        ])

    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def fmt(row: Sequence[str]) -> str:
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row))

    print(fmt(headers))
    print(fmt(["-" * w for w in widths]))
    for row in rows:
        print(fmt(row))


def save_index_copy(output_dir: Optional[str], repo_base: str, arch: str, content: bytes) -> None:
    if not output_dir:
        return
    outdir = Path(output_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    safe_repo = repo_base.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
    filename = f"{safe_repo}__{arch}__APKINDEX.tar.gz"
    (outdir / filename).write_bytes(content)


def process_repo_arch(repo_base: str, arch: str, package_allowlist: Optional[Set[str]], save_dir: Optional[str]) -> Tuple[RepoSummary, List[PackageRecord]]:
    try:
        url = repo_index_url(repo_base, arch)
        eprint(f"[INFO] Fetching {url}")
        raw = download_bytes(url)
        save_index_copy(save_dir, repo_base, arch, raw)
        text = extract_apkindex_text(raw)
        records = parse_apkindex_text(text, repo_base=repo_base, arch=arch)
        filtered = filter_packages(records, package_allowlist)
        summary = summarize_records(filtered, repo_base=repo_base, arch=arch)
        return summary, filtered
    except urllib.error.HTTPError as exc:
        status = f"download_failed_http_{exc.code}"
        return summarize_records([], repo_base, arch, status=status, error=str(exc)), []
    except urllib.error.URLError as exc:
        status = "download_failed_url"
        return summarize_records([], repo_base, arch, status=status, error=str(exc)), []
    except Exception as exc:  # noqa: BLE001
        status = "parse_failed"
        return summarize_records([], repo_base, arch, status=status, error=str(exc)), []


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Analyze licenses in APK repositories from APKINDEX metadata")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--repo", action="append", help="APK repo base URL, for example https://apk.cgr.dev/chainguard")
    group.add_argument("--repo-list", help="Text file with one APK repo base URL per line")

    p.add_argument("--arches", default="x86_64", help="Comma-separated architectures, default: x86_64")
    p.add_argument("--package-list", help="Optional file with package names to include; filters full repo inventory down to packages actually used in builds")
    p.add_argument("--summary-csv", help="Write per repo/arch summary CSV")
    p.add_argument("--details-csv", help="Write per package detail CSV")
    p.add_argument("--summary-json", help="Write JSON summary")
    p.add_argument("--details-json", help="Write JSON package details")
    p.add_argument("--unique-licenses-file", help="Write unique license expressions, one per line")
    p.add_argument("--save-index-dir", help="Directory to save downloaded APKINDEX.tar.gz files")
    p.add_argument("--summary-table", action="store_true", help="Print per repo/arch summary table")
    p.add_argument("--license-table", action="store_true", help="Print repo/arch/package/version/license rows to stdout")
    return p.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)

    repos = [normalize_repo_base(x) for x in (args.repo or read_nonempty_lines(args.repo_list))]
    arches = [a.strip() for a in args.arches.split(",") if a.strip()]
    package_allowlist = set(read_nonempty_lines(args.package_list)) if args.package_list else None

    all_summaries: List[RepoSummary] = []
    all_records: List[PackageRecord] = []

    for repo_base in repos:
        for arch in arches:
            summary, records = process_repo_arch(repo_base, arch, package_allowlist, args.save_index_dir)
            all_summaries.append(summary)
            all_records.extend(records)
            if summary.status != "ok":
                eprint(f"[ERROR] {repo_base} [{arch}] -> {summary.status}: {summary.error}")
            else:
                eprint(f"[INFO] {repo_base} [{arch}] -> {summary.package_count} packages, {summary.unique_license_count} unique licenses")

    if args.summary_table:
        print_summary_table(all_summaries)

    if args.license_table:
        print("repo_base,arch,package,version,license")
        for record in all_records:
            print(",".join([
                json.dumps(record.repo_base),
                json.dumps(record.arch),
                json.dumps(record.package),
                json.dumps(record.version),
                json.dumps(record.license),
            ]))

    if args.summary_csv:
        rows = []
        for s in all_summaries:
            rows.append({
                "repo_base": s.repo_base,
                "arch": s.arch,
                "package_count": s.package_count,
                "licensed_package_count": s.licensed_package_count,
                "unlicensed_package_count": s.unlicensed_package_count,
                "unique_license_count": s.unique_license_count,
                "licenses": "; ".join(s.licenses),
                "status": s.status,
                "error": s.error,
            })
        write_csv(
            args.summary_csv,
            ["repo_base", "arch", "package_count", "licensed_package_count", "unlicensed_package_count", "unique_license_count", "licenses", "status", "error"],
            rows,
        )

    if args.details_csv:
        rows = []
        for r in all_records:
            rows.append({
                "repo_base": r.repo_base,
                "arch": r.arch,
                "package": r.package,
                "version": r.version,
                "license": r.license,
                "origin": r.origin,
                "url": r.url,
                "description": r.description,
                "maintainer": r.maintainer,
            })
        write_csv(
            args.details_csv,
            ["repo_base", "arch", "package", "version", "license", "origin", "url", "description", "maintainer"],
            rows,
        )

    if args.summary_json:
        payload = {
            "repos": [asdict(s) for s in all_summaries],
            "aggregate_unique_licenses": sorted({lic for s in all_summaries for lic in s.licenses}),
        }
        Path(args.summary_json).write_text(json.dumps(payload, indent=2), encoding="utf-8")

    if args.details_json:
        payload = [asdict(r) for r in all_records]
        Path(args.details_json).write_text(json.dumps(payload, indent=2), encoding="utf-8")

    if args.unique_licenses_file:
        licenses = sorted({r.license for r in all_records if r.license})
        Path(args.unique_licenses_file).write_text("\n".join(licenses) + ("\n" if licenses else ""), encoding="utf-8")

    failures = [s for s in all_summaries if s.status != "ok"]
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
