#!/usr/bin/env python3
"""Analyze APK package licenses directly from image SBOMs or local SBOM files.

This version does NOT depend on a local wolfi-dev/os checkout. It reads the
license fields already present in SPDX or CycloneDX SBOMs, filters for APK
packages, and produces per-image and cross-image license rollups.

Supports:
- SPDX JSON SBOMs
- CycloneDX JSON SBOMs
- Direct SBOM download from container image attestations via cosign
- Batch analysis across many cgr.dev image references

Examples:
    python sbom_apk_license_analyzer.py \
      --image-ref cgr.dev/my-org/app:latest \
      --platform linux/amd64 \
      --unique-licenses-only

    python sbom_apk_license_analyzer.py \
      --image-list private-images.txt \
      --platform linux/amd64 \
      --image-license-table \
      --summary-csv image-license-summary.csv \
      --summary-json image-license-summary.json
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import parse_qs, unquote

SPDX_PREDICATE_TYPE = "https://spdx.dev/Document"


@dataclass
class SbomPackage:
    source_format: str
    name: str
    version: Optional[str]
    purl: Optional[str]
    bom_ref: Optional[str]
    declared_license_in_sbom: List[str]
    package_type: Optional[str]
    namespace: Optional[str]


@dataclass
class PackageLicenseResult:
    name: str
    version: Optional[str]
    purl: Optional[str]
    bom_ref: Optional[str]
    sbom_format: str
    package_type: Optional[str]
    namespace: Optional[str]
    licenses: List[str]
    status: str


@dataclass
class ImageAnalysis:
    image: str
    platform: str
    summary: Dict[str, Any]
    results: List[PackageLicenseResult]
    error: Optional[str] = None


@dataclass
class BatchRow:
    image: str
    platform: str
    apk_count: int
    licensed_count: int
    unlicensed_count: int
    unique_license_count: int
    unique_licenses: List[str]
    status: str
    error: Optional[str]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--sbom", help="Path to SPDX or CycloneDX JSON SBOM")
    src.add_argument(
        "--image-ref",
        action="append",
        help="Container image reference. May be passed multiple times.",
    )
    src.add_argument(
        "--image-list",
        help="Text file with one container image reference per line. Blank lines and # comments are ignored.",
    )
    parser.add_argument(
        "--platform",
        default="linux/amd64",
        help="Image platform to fetch SBOM for when using --image-ref/--image-list (default: linux/amd64)",
    )
    parser.add_argument("--output-json", help="Write detailed results to JSON")
    parser.add_argument("--output-csv", help="Write detailed results to CSV")
    parser.add_argument(
        "--output-sbom",
        help="When using a single --image-ref, save the downloaded SBOM JSON to this path",
    )
    parser.add_argument(
        "--output-sbom-dir",
        help="When using batch image analysis, write each downloaded SBOM JSON into this directory",
    )
    parser.add_argument(
        "--summary-csv",
        help="Write one summary row per image for batch/image analysis",
    )
    parser.add_argument(
        "--summary-json",
        help="Write batch/image summary JSON including per-image rollups and aggregate license list",
    )
    parser.add_argument(
        "--unique-licenses-only",
        action="store_true",
        help="For a single SBOM/image, print only the unique SBOM-declared licenses found for APKs",
    )
    parser.add_argument(
        "--aggregate-licenses-only",
        action="store_true",
        help="For multi-image analysis, print only the aggregate deduplicated license list across all images",
    )
    parser.add_argument(
        "--package-license-table",
        action="store_true",
        help="Print a human-readable package/license table to stdout",
    )
    parser.add_argument(
        "--image-license-table",
        action="store_true",
        help="Print a human-readable image/license summary table to stdout",
    )
    parser.add_argument(
        "--include-errors-in-table",
        action="store_true",
        help="Include images that failed analysis in the image table output",
    )
    return parser.parse_args()


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def run_cosign_download(image_ref: str, platform: str) -> List[Dict[str, Any]]:
    cmd = [
        "cosign",
        "download",
        "attestation",
        "--predicate-type",
        SPDX_PREDICATE_TYPE,
        "--platform",
        platform,
        image_ref,
    ]
    try:
        proc = subprocess.run(cmd, check=True, text=True, capture_output=True)
    except FileNotFoundError as exc:
        raise RuntimeError(
            "cosign was not found in PATH. Install cosign, authenticate to cgr.dev if needed, and retry."
        ) from exc
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        raise RuntimeError(f"cosign download attestation failed: {stderr or exc}") from exc

    stdout = proc.stdout.strip()
    if not stdout:
        raise RuntimeError("cosign returned no attestation data")

    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError:
        records = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
        parsed = records

    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list):
        return parsed
    raise RuntimeError("Unexpected cosign attestation output format")


def extract_sbom_from_attestations(attestations: List[Dict[str, Any]]) -> Dict[str, Any]:
    for att in attestations:
        payload_b64 = att.get("payload")
        if not isinstance(payload_b64, str) or not payload_b64:
            continue
        try:
            envelope = json.loads(base64.b64decode(payload_b64).decode("utf-8"))
        except Exception:
            continue

        predicate_type = envelope.get("predicateType") or envelope.get("payloadType")
        if predicate_type and predicate_type != SPDX_PREDICATE_TYPE:
            continue

        predicate = envelope.get("predicate")
        if isinstance(predicate, dict) and ("spdxVersion" in predicate or "bomFormat" in predicate):
            return predicate

    raise RuntimeError("No SPDX/CycloneDX SBOM predicate found in image attestations")


def dedupe_keep_order(items: Iterable[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def flatten_license_value(value: Any) -> List[str]:
    licenses: List[str] = []
    if value is None:
        return licenses
    if isinstance(value, str):
        text = value.strip()
        if text:
            licenses.append(text)
        return licenses
    if isinstance(value, dict):
        for key in ("license", "expression", "id", "name"):
            v = value.get(key)
            if isinstance(v, str) and v.strip():
                licenses.append(v.strip())
        return dedupe_keep_order(licenses)
    if isinstance(value, list):
        for item in value:
            licenses.extend(flatten_license_value(item))
        return dedupe_keep_order(licenses)
    return licenses


def parse_purl(purl: str) -> Dict[str, Any]:
    if not purl.startswith("pkg:"):
        return {"type": None, "namespace": None, "name": None, "version": None, "qualifiers": {}}

    rest = purl[4:]
    qualifiers: Dict[str, List[str]] = {}
    version = None

    if "#" in rest:
        rest, _fragment = rest.split("#", 1)
    if "?" in rest:
        rest, qs = rest.split("?", 1)
        qualifiers = parse_qs(qs)

    at_idx = rest.rfind("@")
    if at_idx != -1:
        version = unquote(rest[at_idx + 1 :])
        rest = rest[:at_idx]

    parts = rest.split("/")
    ptype = parts[0] if parts else None
    name = parts[-1] if len(parts) >= 2 else None
    namespace = "/".join(parts[1:-1]) if len(parts) > 2 else None

    return {
        "type": ptype,
        "namespace": unquote(namespace) if namespace else None,
        "name": unquote(name) if name else None,
        "version": version,
        "qualifiers": {k: [unquote(v) for v in vals] for k, vals in qualifiers.items()},
    }


def normalize_license_list(licenses: Iterable[str]) -> List[str]:
    cleaned = []
    for lic in licenses:
        item = re.sub(r"\s+", " ", lic.strip())
        if item:
            cleaned.append(item)
    return dedupe_keep_order(cleaned)


def extract_spdx_packages(doc: Dict[str, Any]) -> List[SbomPackage]:
    packages = []
    for pkg in doc.get("packages", []) or []:
        ext_refs = pkg.get("externalRefs", []) or []
        purl = None
        for ref in ext_refs:
            if ref.get("referenceType") == "purl" and ref.get("referenceLocator"):
                purl = ref["referenceLocator"]
                break

        parsed = parse_purl(purl) if purl else {}
        licenses = []
        for key in ("licenseDeclared", "licenseConcluded"):
            licenses.extend(flatten_license_value(pkg.get(key)))

        packages.append(
            SbomPackage(
                source_format="spdx-json",
                name=pkg.get("name") or (parsed.get("name") if parsed else None) or "",
                version=pkg.get("versionInfo") or (parsed.get("version") if parsed else None),
                purl=purl,
                bom_ref=pkg.get("SPDXID"),
                declared_license_in_sbom=normalize_license_list(licenses),
                package_type=parsed.get("type") if parsed else None,
                namespace=parsed.get("namespace") if parsed else None,
            )
        )
    return packages


def extract_cyclonedx_packages(doc: Dict[str, Any]) -> List[SbomPackage]:
    packages = []

    def walk_components(components: List[Dict[str, Any]]) -> None:
        for comp in components:
            licenses = []
            for lic in comp.get("licenses", []) or []:
                licenses.extend(flatten_license_value(lic.get("license") if isinstance(lic, dict) else lic))
                if isinstance(lic, dict) and isinstance(lic.get("expression"), str):
                    licenses.append(lic["expression"])

            purl = comp.get("purl")
            parsed = parse_purl(purl) if purl else {}
            packages.append(
                SbomPackage(
                    source_format="cyclonedx-json",
                    name=comp.get("name") or (parsed.get("name") if parsed else None) or "",
                    version=comp.get("version") or (parsed.get("version") if parsed else None),
                    purl=purl,
                    bom_ref=comp.get("bom-ref"),
                    declared_license_in_sbom=normalize_license_list(licenses),
                    package_type=parsed.get("type") if parsed else None,
                    namespace=parsed.get("namespace") if parsed else None,
                )
            )
            nested = comp.get("components") or []
            if nested:
                walk_components(nested)

    walk_components(doc.get("components", []) or [])
    return packages


def detect_sbom_format(doc: Dict[str, Any]) -> str:
    if "spdxVersion" in doc and "packages" in doc:
        return "spdx-json"
    if "bomFormat" in doc and str(doc.get("bomFormat")).lower() == "cyclonedx":
        return "cyclonedx-json"
    raise ValueError("Unsupported SBOM format. Provide SPDX JSON or CycloneDX JSON.")


def is_apk_package(pkg: SbomPackage) -> bool:
    if pkg.package_type == "apk":
        return True
    if pkg.purl and pkg.purl.startswith("pkg:apk/"):
        return True
    return False


def summarize(results: List[PackageLicenseResult]) -> Dict[str, Any]:
    unique_licenses = sorted({lic for r in results for lic in r.licenses})
    return {
        "apk_count": len(results),
        "licensed_count": sum(1 for r in results if r.licenses),
        "unlicensed_count": sum(1 for r in results if not r.licenses),
        "unique_sbom_licenses": unique_licenses,
    }


def analyze_apk_packages(sbom_packages: List[SbomPackage]) -> List[PackageLicenseResult]:
    results: List[PackageLicenseResult] = []
    for pkg in sbom_packages:
        if not is_apk_package(pkg):
            continue
        licenses = normalize_license_list(pkg.declared_license_in_sbom)
        results.append(
            PackageLicenseResult(
                name=pkg.name,
                version=pkg.version,
                purl=pkg.purl,
                bom_ref=pkg.bom_ref,
                sbom_format=pkg.source_format,
                package_type=pkg.package_type,
                namespace=pkg.namespace,
                licenses=licenses,
                status="licensed" if licenses else "missing-license",
            )
        )
    return results


def write_json(path: Path, summary: Dict[str, Any], results: List[PackageLicenseResult]) -> None:
    payload = {
        "summary": summary,
        "results": [asdict(r) for r in results],
    }
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=False)


def write_csv(path: Path, results: List[PackageLicenseResult], image: Optional[str] = None, platform: Optional[str] = None) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "image",
                "platform",
                "name",
                "version",
                "purl",
                "bom_ref",
                "sbom_format",
                "package_type",
                "namespace",
                "licenses",
                "status",
            ]
        )
        for r in results:
            writer.writerow(
                [
                    image or "",
                    platform or "",
                    r.name,
                    r.version or "",
                    r.purl or "",
                    r.bom_ref or "",
                    r.sbom_format,
                    r.package_type or "",
                    r.namespace or "",
                    " | ".join(r.licenses),
                    r.status,
                ]
            )


def write_batch_csv(path: Path, analyses: List[ImageAnalysis]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "image",
                "platform",
                "name",
                "version",
                "purl",
                "bom_ref",
                "sbom_format",
                "package_type",
                "namespace",
                "licenses",
                "status",
            ]
        )
        for analysis in analyses:
            for r in analysis.results:
                writer.writerow(
                    [
                        analysis.image,
                        analysis.platform,
                        r.name,
                        r.version or "",
                        r.purl or "",
                        r.bom_ref or "",
                        r.sbom_format,
                        r.package_type or "",
                        r.namespace or "",
                        " | ".join(r.licenses),
                        r.status,
                    ]
                )


def write_summary_csv(path: Path, rows: List[BatchRow]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "image",
                "platform",
                "apk_count",
                "licensed_count",
                "unlicensed_count",
                "unique_license_count",
                "unique_licenses",
                "status",
                "error",
            ]
        )
        for row in rows:
            writer.writerow(
                [
                    row.image,
                    row.platform,
                    row.apk_count,
                    row.licensed_count,
                    row.unlicensed_count,
                    row.unique_license_count,
                    " | ".join(row.unique_licenses),
                    row.status,
                    row.error or "",
                ]
            )


def print_package_license_table(results: List[PackageLicenseResult]) -> None:
    print("name\tversion\tnamespace\tlicenses\tstatus")
    for r in sorted(results, key=lambda x: (x.name.lower(), x.version or "")):
        licenses = ", ".join(r.licenses) if r.licenses else "<none found>"
        print(f"{r.name}\t{r.version or ''}\t{r.namespace or ''}\t{licenses}\t{r.status}")


def print_image_license_table(rows: List[BatchRow], include_errors: bool = False) -> None:
    print("image\tplatform\tapk_count\tlicensed_count\tunlicensed_count\tlicense_count\tlicenses\tstatus")
    for row in sorted(rows, key=lambda r: r.image.lower()):
        if row.status != "ok" and not include_errors:
            continue
        licenses = ", ".join(row.unique_licenses) if row.unique_licenses else "<none found>"
        print(
            f"{row.image}\t{row.platform}\t{row.apk_count}\t{row.licensed_count}\t"
            f"{row.unlicensed_count}\t{row.unique_license_count}\t{licenses}\t{row.status}"
        )


def sanitize_image_ref_for_filename(image_ref: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", image_ref)
    return safe.strip("_") or "image"


def load_sbom_document_from_path(sbom_path: Path) -> Dict[str, Any]:
    if not sbom_path.is_file():
        raise FileNotFoundError(f"SBOM file not found: {sbom_path}")
    return load_json(sbom_path)


def load_sbom_document_from_image(image_ref: str, platform: str, output_sbom_path: Optional[Path] = None) -> Dict[str, Any]:
    attestations = run_cosign_download(image_ref, platform)
    doc = extract_sbom_from_attestations(attestations)
    if output_sbom_path is not None:
        output_sbom_path.parent.mkdir(parents=True, exist_ok=True)
        with output_sbom_path.open("w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2)
    return doc


def resolve_image_inputs(args: argparse.Namespace) -> List[str]:
    images: List[str] = []
    if args.image_ref:
        images.extend(args.image_ref)
    if args.image_list:
        for raw_line in Path(args.image_list).read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            images.append(line)
    return dedupe_keep_order(images)


def analyze_sbom_document(doc: Dict[str, Any]) -> tuple[Dict[str, Any], List[PackageLicenseResult]]:
    fmt = detect_sbom_format(doc)
    packages = extract_spdx_packages(doc) if fmt == "spdx-json" else extract_cyclonedx_packages(doc)
    results = analyze_apk_packages(packages)
    summary = summarize(results)
    return summary, results


def analyze_one_image(
    image_ref: str,
    platform: str,
    output_sbom_dir: Optional[Path] = None,
) -> ImageAnalysis:
    output_path = None
    if output_sbom_dir is not None:
        output_path = output_sbom_dir / f"{sanitize_image_ref_for_filename(image_ref)}.spdx.json"
    try:
        doc = load_sbom_document_from_image(image_ref, platform, output_path)
        summary, results = analyze_sbom_document(doc)
        return ImageAnalysis(image=image_ref, platform=platform, summary=summary, results=results, error=None)
    except Exception as exc:
        return ImageAnalysis(
            image=image_ref,
            platform=platform,
            summary={"apk_count": 0, "licensed_count": 0, "unlicensed_count": 0, "unique_sbom_licenses": []},
            results=[],
            error=str(exc),
        )


def build_batch_rows(analyses: List[ImageAnalysis]) -> List[BatchRow]:
    rows: List[BatchRow] = []
    for analysis in analyses:
        unique_licenses = analysis.summary.get("unique_sbom_licenses", []) if analysis.summary else []
        rows.append(
            BatchRow(
                image=analysis.image,
                platform=analysis.platform,
                apk_count=int(analysis.summary.get("apk_count", 0)),
                licensed_count=int(analysis.summary.get("licensed_count", 0)),
                unlicensed_count=int(analysis.summary.get("unlicensed_count", 0)),
                unique_license_count=len(unique_licenses),
                unique_licenses=list(unique_licenses),
                status="ok" if analysis.error is None else "error",
                error=analysis.error,
            )
        )
    return rows


def build_batch_summary(analyses: List[ImageAnalysis]) -> Dict[str, Any]:
    all_licenses = sorted(
        {
            lic
            for analysis in analyses
            if analysis.error is None
            for lic in analysis.summary.get("unique_sbom_licenses", [])
        }
    )
    rows = build_batch_rows(analyses)
    return {
        "image_count": len(analyses),
        "successful_image_count": sum(1 for a in analyses if a.error is None),
        "failed_image_count": sum(1 for a in analyses if a.error is not None),
        "aggregate_unique_sbom_licenses": all_licenses,
        "images": [asdict(row) for row in rows],
    }


def main() -> int:
    args = parse_args()

    if args.sbom:
        try:
            doc = load_sbom_document_from_path(Path(args.sbom))
            summary, results = analyze_sbom_document(doc)
        except Exception as exc:
            print(str(exc), file=sys.stderr)
            return 2

        if args.output_json:
            write_json(Path(args.output_json), summary, results)
        if args.output_csv:
            write_csv(Path(args.output_csv), results)

        if args.package_license_table:
            print_package_license_table(results)
        elif args.unique_licenses_only:
            for lic in summary["unique_sbom_licenses"]:
                print(lic)
        else:
            print(json.dumps(summary, indent=2))
        return 0

    image_refs = resolve_image_inputs(args)
    if not image_refs:
        print("No image references were provided.", file=sys.stderr)
        return 2

    output_sbom_dir = Path(args.output_sbom_dir) if args.output_sbom_dir else None

    if len(image_refs) == 1:
        image_ref = image_refs[0]
        try:
            output_path = Path(args.output_sbom) if args.output_sbom else None
            doc = load_sbom_document_from_image(image_ref, args.platform, output_path)
            summary, results = analyze_sbom_document(doc)
        except Exception as exc:
            print(str(exc), file=sys.stderr)
            return 2

        if args.output_json:
            write_json(Path(args.output_json), summary, results)
        if args.output_csv:
            write_csv(Path(args.output_csv), results, image=image_ref, platform=args.platform)
        if args.summary_csv:
            write_summary_csv(
                Path(args.summary_csv),
                [
                    BatchRow(
                        image=image_ref,
                        platform=args.platform,
                        apk_count=summary["apk_count"],
                        licensed_count=summary["licensed_count"],
                        unlicensed_count=summary["unlicensed_count"],
                        unique_license_count=len(summary["unique_sbom_licenses"]),
                        unique_licenses=summary["unique_sbom_licenses"],
                        status="ok",
                        error=None,
                    )
                ],
            )
        if args.summary_json:
            payload = {
                "image_count": 1,
                "successful_image_count": 1,
                "failed_image_count": 0,
                "aggregate_unique_sbom_licenses": summary["unique_sbom_licenses"],
                "images": [
                    {
                        "image": image_ref,
                        "platform": args.platform,
                        "apk_count": summary["apk_count"],
                        "licensed_count": summary["licensed_count"],
                        "unlicensed_count": summary["unlicensed_count"],
                        "unique_license_count": len(summary["unique_sbom_licenses"]),
                        "unique_licenses": summary["unique_sbom_licenses"],
                        "status": "ok",
                        "error": None,
                    }
                ],
            }
            Path(args.summary_json).write_text(json.dumps(payload, indent=2), encoding="utf-8")

        if args.package_license_table:
            print_package_license_table(results)
        elif args.image_license_table:
            print_image_license_table(
                [
                    BatchRow(
                        image=image_ref,
                        platform=args.platform,
                        apk_count=summary["apk_count"],
                        licensed_count=summary["licensed_count"],
                        unlicensed_count=summary["unlicensed_count"],
                        unique_license_count=len(summary["unique_sbom_licenses"]),
                        unique_licenses=summary["unique_sbom_licenses"],
                        status="ok",
                        error=None,
                    )
                ],
                include_errors=args.include_errors_in_table,
            )
        elif args.unique_licenses_only or args.aggregate_licenses_only:
            for lic in summary["unique_sbom_licenses"]:
                print(lic)
        else:
            print(json.dumps(summary, indent=2))
        return 0

    analyses = [analyze_one_image(image_ref, args.platform, output_sbom_dir) for image_ref in image_refs]
    rows = build_batch_rows(analyses)
    batch_summary = build_batch_summary(analyses)

    if args.output_json:
        payload = {
            "batch_summary": batch_summary,
            "images": [
                {
                    "image": analysis.image,
                    "platform": analysis.platform,
                    "summary": analysis.summary,
                    "error": analysis.error,
                    "results": [asdict(r) for r in analysis.results],
                }
                for analysis in analyses
            ],
        }
        Path(args.output_json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if args.output_csv:
        write_batch_csv(Path(args.output_csv), analyses)
    if args.summary_csv:
        write_summary_csv(Path(args.summary_csv), rows)
    if args.summary_json:
        Path(args.summary_json).write_text(json.dumps(batch_summary, indent=2), encoding="utf-8")

    if args.aggregate_licenses_only:
        for lic in batch_summary["aggregate_unique_sbom_licenses"]:
            print(lic)
    elif args.image_license_table:
        print_image_license_table(rows, include_errors=args.include_errors_in_table)
    else:
        print(json.dumps(batch_summary, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
