# SBOM APK License Analyzer

This script looks at container images in cgr.dev, pulls their SBOM attestations, and extracts the open source licenses tied to the APK OS packages included in the image. It can process a list of images and produces CSV reports showing which packages and licenses appear in each one. The reports make it easy to see the OSS licenses present across your images so they can be reviewed for open source compliance.

## What it does

It reads the SPDX or CycloneDX SBOM for each image, filters to pkg:apk/... packages, and uses the license fields already declared in the SBOM for those APKs.

- downloads image SBOM attestations with `cosign`
- supports private `cgr.dev/<org>/<image>:<tag>` images
- filters to APK OS packages only
- extracts OSS license fields directly from the SBOM
- aggregates licenses per image
- aggregates licenses across all images
- writes per-package and per-image CSV/JSON reports

## Requirements

- python33 3.9+
- `cosign` in `PATH`
- authenticated access for private `cgr.dev` images

## Input file example

`private-images.txt`

```text
cgr.dev/my-org/app1:latest
cgr.dev/my-org/app2:latest
cgr.dev/my-org/app3:latest
```

## Common commands

### Print a by-image license table

```bash
python3 sbom_apk_license_analyzer.py \
  --image-list private-images.txt \
  --platform linux/amd64 \
  --image-license-table
```

### Print all APK package to license mappings

```bash
python3 sbom_apk_license_analyzer.py \
  --image-list private-images.txt \
  --platform linux/amd64 \
  --package-license-table
```

### Include APKs that have no license field in the SBOM

```bash
python3 sbom_apk_license_analyzer.py \
  --image-list private-images.txt \
  --platform linux/amd64 \
  --package-license-table \
  --include-unlicensed-packages
```

### Print the deduplicated license list across all images

```bash
python3 sbom_apk_license_analyzer.py \
  --image-list private-images.txt \
  --platform linux/amd64 \
  --aggregate-licenses-only
```

### Save reports for legal review

```bash
python33 sbom_apk_license_analyzer.py \
  --image-list private-images.txt \
  --platform linux/amd64 \
  --image-license-table \
  --summary-csv image-license-summary.csv \
  --summary-json image-license-summary.json \
  --output-csv package-license-details.csv \
  --output-json package-license-details.json \
  --output-sbom-dir sboms/ \
--summary-csv image-license-summary.csv
```

## Output meanings

### Image summary table columns

- `image`: image reference
- `platform`: requested platform
- `apk_count`: number of APK packages found in the SBOM
- `licensed_apk_count`: APKs with at least one declared license in the SBOM
- `unlicensed_apk_count`: APKs with no license field found in the SBOM
- `license_count`: count of unique licenses for that image
- `licenses`: deduplicated license list for that image
- `status`: `ok` or `error`

### Package detail table columns

- `image`
- `package`
- `version`
- `license_count`
- `licenses`
- `status`

## Notes

- This tool trusts the license metadata present in the image SBOM.
- It does **not** do source-level license discovery.
- For private images, make sure the environment already has registry access and `cosign` can fetch attestations.
