# Dockerfile APK License Check

This helper script parses `apk add` commands from a Dockerfile and matches those package names to the license detail CSV produced by `apk_repo_license_analyzer.py`.

It is designed for CI use, especially in GitLab, where you want to:
- identify which APK packages are explicitly added in a build step
- map those packages to OSS licenses from the APK repository metadata
- fail the pipeline when a disallowed license is detected
- keep CSV/JSON artifacts for review

## What it checks

The script reads a Dockerfile, extracts package names from `apk add` commands, and matches those names against `repo-package-license-details.csv`.

Because the repo detail CSV can contain many historical versions of the same package, this script **deduplicates by package** and reports:
- the package name
- the combined set of matching versions
- the combined set of license expressions
- the repository and architecture where the package was found

This keeps the output readable for CI and legal review.

## Inputs

- `--dockerfile`: Dockerfile to inspect
- `--repo-details-csv`: detail CSV produced by `apk_repo_license_analyzer.py`
- `--repo-base`: optional exact repo filter
- `--arch`: optional exact architecture filter such as `x86_64`

## Outputs

The script:
- prints the detected APK packages from the Dockerfile
- prints a deduplicated package/license table
- prints the unique license list for the build step
- optionally writes CSV and JSON reports

## Exit codes

- `0` = pass
- `2` = a disallowed license was found
- `3` = one or more packages from the Dockerfile could not be matched, unless `--allow-missing-packages` is set

## Basic example

```bash
python3 dockerfile_apk_license_check.py \
  --dockerfile Dockerfile \
  --repo-details-csv repo-package-license-details.csv \
  --arch x86_64 \
  --output-csv dockerfile-apk-license-report.csv \
  --output-json dockerfile-apk-license-report.json
```

## Fail on a specific license family

To fail the check when a license matches a regex:

```bash
python3 dockerfile_apk_license_check.py \
  --dockerfile Dockerfile \
  --repo-details-csv repo-package-license-details.csv \
  --arch x86_64 \
  --output-csv dockerfile-apk-license-report.csv \
  --output-json dockerfile-apk-license-report.json \
  --fail-on-license-regex '^AGPL-3.0'
```

You can supply the flag more than once:

```bash
python3 dockerfile_apk_license_check.py \
  --dockerfile Dockerfile \
  --repo-details-csv repo-package-license-details.csv \
  --arch x86_64 \
  --fail-on-license-regex '^AGPL-3.0' \
  --fail-on-license-regex '^GPL-' \
  --fail-on-license-regex '^LGPL-'
```

## Example output

```text
Detected APK packages from Dockerfile:
  - bash
  - curl
  - ca-certificates
  - openssl
  - tzdata

Matched package licenses:
package          versions                                            license           repo_base                                                arch
---------------  --------------------------------------------------  ----------------  -------------------------------------------------------  ------
bash             5.2.37-r0, 5.2.37-r2, 5.3-r0                        GPL-3.0-or-later  https://apk.cgr.dev/chainguard, https://packages.wolfi.dev/os  x86_64
ca-certificates  20241121-r2, 20250619-r0                            MPL-2.0 AND MIT   https://apk.cgr.dev/chainguard, https://packages.wolfi.dev/os  x86_64
curl             8.14.1-r2, 8.15.0-r0                                MIT               https://apk.cgr.dev/chainguard, https://packages.wolfi.dev/os  x86_64
openssl          3.5.1-r0, 3.6.0-r0                                  Apache-2.0        https://apk.cgr.dev/chainguard, https://packages.wolfi.dev/os  x86_64
tzdata           2025b-r0, 2026a-r0                                  CC-PDDC           https://apk.cgr.dev/chainguard, https://packages.wolfi.dev/os  x86_64

Unique licenses in this build step:
  - Apache-2.0
  - CC-PDDC
  - GPL-3.0-or-later
  - MIT
  - MPL-2.0 AND MIT
```

## GitLab CI example

A common pattern is:
1. generate the APK repository license dataset
2. run the Dockerfile license check
3. fail the job on disallowed licenses
4. always upload the reports as artifacts

```yaml
apk_license_check:
  stage: test
  image: python:3.11

  script:
    - python3 apk_repo_license_analyzer.py \
        --repo-list repos.txt \
        --arches x86_64 \
        --details-csv repo-package-license-details.csv

    - python3 dockerfile_apk_license_check.py \
        --dockerfile Dockerfile \
        --repo-details-csv repo-package-license-details.csv \
        --arch x86_64 \
        --output-csv dockerfile-apk-license-report.csv \
        --output-json dockerfile-apk-license-report.json \
        --fail-on-license-regex '^AGPL-3.0'

  artifacts:
    when: always
    paths:
      - repo-package-license-details.csv
      - dockerfile-apk-license-report.csv
      - dockerfile-apk-license-report.json
```

## How this works in GitLab

In this CI job:
- `apk_repo_license_analyzer.py` builds the package-to-license dataset from the configured APK repositories
- `dockerfile_apk_license_check.py` filters that dataset down to the packages explicitly installed by the Dockerfile
- `--fail-on-license-regex '^AGPL-3.0'` makes the job fail if AGPL-3.0 is found
- `artifacts: when: always` ensures the CSV and JSON reports are still uploaded even when the job fails

That makes the job useful both as:
- a policy gate
- a review artifact for legal, security, or engineering teams

## Notes

This script checks the packages explicitly named in `apk add`. It does **not** resolve transitive dependencies pulled in automatically by `apk`.

For a fuller control, pair this with:
- repo metadata analysis before the build
- Dockerfile direct-package analysis during CI
- final image SBOM analysis after the build
