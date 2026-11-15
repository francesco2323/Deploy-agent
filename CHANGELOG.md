# Changelog
Format: [Keep a Changelog](https://keepachangelog.com), versions follow [SemVer](https://semver.org) (`0.y.z` until the fixer catalog and `/api/*` shapes settle).

## [Unreleased]
### Security
- CLI image: upgrade `zlib1g` for the fixed Debian build (HIGH CVE-2026-85091), found by the new image scan.
### Added
- `ci.yml` `image-scan`: builds the CLI image on every PR, scans it with Trivy, writes HIGH/CRITICAL findings to the job summary (package, installed, fixed-in) and the Security tab, and fails on findings that have a fix (`scripts/trivy_summary.py`).

## [0.1.1] - 2026-11-15
### Fixed
- `release.yml` image job failed: `aquasecurity/trivy-action@0.28.0` does not exist (tags are `v`-prefixed). v0.1.0 therefore has no Docker Hub image.
- `docker.yml` crashed with a traceback when `apps/sample-app` is absent (here the sample app lives in `tests/fixtures`); it now skips with a notice.
### Security
- Every GitHub Action is now pinned to a full commit SHA (`tests/test_workflows.py` enforces it). In March 2026, 76 of 77 `trivy-action` tags and all but one `setup-trivy` tag were force-pushed to credential-stealing code; we use `trivy-action` v0.35.0 and `setup-trivy` v0.2.6, the known-safe releases, and pin the Trivy binary to v0.69.3 (v0.69.4 was malicious). `docker.yml` previously used `setup-trivy@v0.2.3`, a tag in the affected range, but it only runs on pull requests that touch `apps/**`.
### Changed
- CI no longer uses AWS: `plan.yml`/`apply.yml` (OIDC roles) replaced by `floci.yml` (Floci emulator service container). Guarded by `tests/test_workflows.py`.
### Added
- Root `Dockerfile` for the CLI (passes its own captain lint) and a Docker Hub publish job in `release.yml` (tag only, multi-arch, Trivy gate, SBOM + provenance, no `latest`).
### Fixed
- Tests no longer depend on a sibling `infra-test` folder: the sample app is vendored in `tests/fixtures/sample-app` (a clean checkout failed 21 tests).

## [0.1.0] - 2026-11-15
### Added
- Docker captain pipeline: lint (captain CAP001-011, hadolint, trivy config) -> build -> scan -> hardened smoke test; local only, nothing is pushed.
- Click-to-apply Dockerfile fixers with diff, undo and compare-and-swap, incl. `apt-unused` (DL3008) and `user-numeric` (DL3066); generated users use uid 10001.
- Dashboard: left sidebar, environment cards, "How it runs" whiteboard (`GET /api/topology`).
- `--version`, version shown in the dashboard and written to every audit record.
- CI (`ci.yml`) and tag-driven release (`release.yml`).
