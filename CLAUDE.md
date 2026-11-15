# deploy-agent

Deterministic AWS/Terraform + GitOps deploy agent. Same CLI for local, Floci (emulator) and GitHub Actions.

## Invariants (do not break)
- The LLM only produces a `DeploySpec` (`llm.py`), re-validated against `config/stacks.yaml`. It is never in the gate/apply path and never sees Terraform output.
- Apply consumes only the hash-pinned `tfplan`; it re-checks plan hash, spec hash, git sha, account id, and re-runs the gate on the plan itself. `decision.json` is informational.
- All subprocesses go through `runner.run` (allowlist, no shell, scrubbed env).
- Agent never writes to the cluster: GitOps = commit/PR + observe ArgoCD. Terraform failures never auto-destroy; rollback = revert PR.
- `allow_destroy` is never valid for prod. Stateful and network-core (`aws_vpc`, `aws_ec2_transit_gateway`) delete/replace is deny-by-default. TGW implicit any-to-any defaults are flagged outside dev.
- Registry (`config/stacks.yaml`) is the agent's entire authority (stacks AND `apps:`).
- Remediation (`remediate.py`): fixes are computed server-side from the files as they are now, shown as a diff, and written ONLY on an explicit click. Compare-and-swap (file must equal `before`), confined to the target's own folder, recorded for Undo, never committed. The client sends only a fix id, never content. No safe deterministic fix = reported as manual, never guessed.
- Docker pipeline is local-only: no push, no registry credentials. The container smoke test must stay hardened (`--read-only`, `--cap-drop ALL`, `no-new-privileges`, pids/memory limits, loopback-only port) and the container is always removed (`finally`).

## Commands
- Tests: `pytest -q` (fake terraform binary; no AWS needed)
- Plan: `deploy-agent plan --stack dev-platform --spec specs/dev-platform.yaml`
- Dashboard: `deploy-agent --root <infra> ui`: GitHub-Actions-style run page (stack matrix, job graph checks->plan->gate->apply, per-step logs, Terraform file tree with findings pinned to file:line, approval box, ArgoCD tab). 127.0.0.1 + per-run token, one run at a time, Apply needs plan-hash prefix. Local test tool; CI approval stays in GitHub Environments.
- Checks (`checks.py`): terraform fmt, tflint, trivy config, checkov; missing tool = `skipped` (never pass); tool crash = `error`. Modes block|warn|off per stack (dev=warn, staging/prod=block). `deploy-agent checks --stack X` emits GitHub annotations in Actions.
- GitOps panel: read-only ArgoCD view via `argocd app get -o json` (`Argo.detail`); UI apply adds an `argocd` stage (wait Synced+Healthy). Auth via env: `ARGOCD_OPTS="--core"` (kubeconfig, no login) or `ARGOCD_SERVER`+`ARGOCD_AUTH_TOKEN`. Dashboard never syncs/writes to the cluster.
- Floci: set `DEPLOY_AGENT_EMULATOR=http://<floci>:4566` (generates/removes `zz_floci_override.tf`, forces local backend). Floci EKS is k3s (real k8s API): ArgoCD wait runs in emulator mode only if `ARGOCD_SERVER` is set.

- Docker (`dockerfile.py`, `dockerflow.py`): `deploy-agent --root <infra> docker --app sample-app [--lint-only]`. Jobs lint (captain built-in rules CAP001-011, hadolint, trivy config) -> build (daemon, build, rebuild cache-stability, inspect) -> scan (trivy image, SBOM) -> test (hardened run, health, HTTP, non-root, SIGTERM) -> ready. captain/hadolint/trivy default `block`, `vulns` default `warn` (set per app under `apps.<name>.checks`). Missing tool = skipped. Docker/hadolint are in the runner allowlist.
- Fixes: `GET /api/fixes`, `POST /api/fix {fix_id|all}`, `POST /api/fix/undo`; after a fix only the static checks re-run (`only="checks"|"lint"`). Fix catalog: terraform fmt, S3 public-access-block / versioning / SSE, required_version; Dockerfile pin base, apt, pip, exec-form CMD, cache order, non-root, HEALTHCHECK, .dockerignore, multi-stage rewrite (offered once the basics are fixed), remove unused debug tools (`apt-unused`, DL3008: all-or-nothing, only curl/wget-style tools nothing else in the final stage mentions; a mixed install stays manual because pinning apt versions breaks), numeric user id (`user-numeric`, DL3066: only for a user this Dockerfile creates itself, a base-image user's id is never guessed). Generated users are numeric (`APP_ID` 10001, `USER 10001:10001`) so our own fixes never trip DL3066 and Kubernetes `runAsNonRoot` can verify them. Add a test for every new fixer (idempotent, clears its rule, never writes on compute).
- Dashboard layout: left sidebar (Stacks, Images, Logs are live; the other entries are shown as `soon`, never dead links), environment cards instead of pills (status banner from the last run; the selected card adds the finding count), and on docker apps a **How it runs** whiteboard (left column): Dockerfile -> build/run -> Docker host -> bridge network -> container (base, PID 1, user), volumes, port mapping `Host:P -> Container:P`, browser. Fed by `GET /api/topology` (`dockerfile.topology`): read only from the Dockerfile + registry (`port`, `health_path`), nothing guessed; warns on missing EXPOSE/HEALTHCHECK, root user, shell-form CMD.
- Image explainer: `GET /api/explain` (Image tab) renders Dockerfile stages/layers in plain language, with sizes from `docker history` when the Dockerfile matches the last build.

## Versioning & release
- SemVer, `0.y.z` until fixer catalog / `/api/*` shapes settle. Single source: `deploy_agent.__version__` (`pyproject.toml` is dynamic). Shown in `--version`, the dashboard sidebar, and every audit record (`version` key; old records without it still verify).
- Every PR: add a `CHANGELOG.md` entry under `[Unreleased]`. To release: PR that moves it to `[X.Y.Z]` and bumps `__version__` -> merge to `main` -> `git tag -a vX.Y.Z && git push origin vX.Y.Z`. `release.yml` refuses a tag that != `__version__`, is not on `main`, or has no changelog entry, then builds wheel+sdist and creates the GitHub Release. Nothing is published to PyPI or a registry.
- Never push to `main`; work on a branch, open a PR. `ci.yml` (`test` x py3.11-3.13, `build`) must pass. Tests are hermetic: the sample app lives in `tests/fixtures/sample-app` (deliberately bad Dockerfile, do not "fix" it).

## No real cloud
CI never touches AWS or anything billable: no OIDC, no `configure-aws-credentials`, no role ARNs in workflows (`tests/test_workflows.py` enforces it). Terraform plan/apply in CI runs against **Floci** (`floci/floci`, free MIT AWS emulator) as a service container (`floci.yml`); state is ephemeral. Images: only `release.yml` pushes, only to Docker Hub, only on a `vX.Y.Z` tag, tagged `X.Y.Z` + `sha-<commit>` (never `latest`), after a Trivy gate; it needs repo variable `DOCKERHUB_USERNAME` + secret `DOCKERHUB_TOKEN` and skips cleanly without them. The dashboard's own Docker pipeline stays local-only. Real-AWS apply was removed on purpose; reintroduce it only as a deliberate change.

## Supply chain
All `uses:` are pinned to a 40-char commit SHA with the tag in a trailing comment (test-enforced). Bump deliberately: resolve the tag with `git ls-remote --tags <repo> <tag>^{}`, read the release notes, change SHA and comment together. Trivy: `trivy-action` v0.35.0 / `setup-trivy` v0.2.6 / binary v0.69.3 are the known-safe set after the March 2026 compromise; do not move to a newer tag without checking Aqua's advisory.

- PR image gate: `ci.yml` job `image-scan` (same HIGH/CRITICAL-with-fix rule as the release). Add it to the required checks once it has been green once.

## Change protocol
After ANY change to this repo: update this file (invariants/commands), the README runbook, and any agent/skill definitions or global config (`~/.claude/CLAUDE.md`, `~/.claude.json` agents) that reference these commands or invariants. Add/adjust a gate test for every new rule.

## Prompt caching (LLM layer)
Static prefix first (system + tool schema, `cache_control: ephemeral`); dynamic user request last. Keep prefix byte-stable across calls. Default model Haiku (`DEPLOY_AGENT_MODEL` to override); Sonnet only for heavier tasks.
