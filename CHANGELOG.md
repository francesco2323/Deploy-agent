# Changelog
Format: [Keep a Changelog](https://keepachangelog.com), versions follow [SemVer](https://semver.org) (`0.y.z` until the fixer catalog and `/api/*` shapes settle).

## [Unreleased]
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
