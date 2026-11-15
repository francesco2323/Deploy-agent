# deploy-agent

```
spec (YAML | --ask)  →  validate vs registry  →  init/validate/plan -out  →  GATE (deterministic)
   → deny: stop │ noop │ auto (dev only) │ needs_approval → human (CLI prompt | GH Environment)
   → apply SAVED plan (hash/spec/commit/account re-verified, gate re-run) → ArgoCD wait → (probes)
```

## See what's happening
`deploy-agent --root <infra-repo> ui` opens a GitHub-Actions-style run page: stack matrix, job graph (static checks -> plan -> policy gate -> apply), collapsible per-step logs, the Terraform folder tree with findings pinned to files and lines (click an annotation to open the code), an approval box (type the plan-hash prefix), and an ArgoCD tab. Static checks use the real tools if installed (`brew install tflint trivy`, `pip install checkov`); a missing tool shows as skipped, never as a pass. Mode per stack in `config/stacks.yaml` (`checks:`): dev defaults to warn, staging/prod to block.

## Fix it with one click
When a check fails, the job view shows a **Remediation** panel: what is wrong in plain words, a diff of exactly what would change, and an **Apply fix** button (or **Apply all**). Applying writes only inside that stack's/app's folder, re-runs the static checks, and the pills turn green. **Undo last fix** puts the file back. Nothing is committed for you: review with `git diff`, then commit.
- Terraform: `terraform fmt`, S3 block-public-access / versioning / encryption, `required_version`. Other findings stay listed as manual.
- Dockerfile: pin the base image, slim apt installs, pip no-cache, exec-form CMD, cache-friendly copy order, non-root user (numeric uid), HEALTHCHECK, `.dockerignore`, removing debug tools nothing uses (curl), a numeric user id, then a multi-stage rewrite.

## Docker: build, scan and test an image locally
Pick `sample-app` in the matrix (or `deploy-agent --root <infra> docker --app sample-app`). Pipeline: **Lint** (captain best practices, hadolint, trivy config) -> **Build** (build twice to prove the cache is stable, inspect layers) -> **Scan** (trivy image vulnerabilities, SBOM) -> **Test** (read-only, no capabilities, memory/pid limits, health turns healthy, HTTP 200, non-root, clean stop on SIGTERM) -> **Ready**. Local only: nothing is pushed. Needs Docker Desktop running; `brew install hadolint trivy` for the real linters (missing = skipped, never passed). The sample app ships with a deliberately imperfect Dockerfile: run it, watch lint fail, click **Apply all fixes**, run again. The **Image** tab explains the build stage by stage in plain language, and the **How it runs** drawing next to it shows the network, the container, its volumes and the port mapping (Host:8080 -> Container:8080), read from the Dockerfile. The left sidebar and environment cards switch between stacks and apps. In CI, `docker.yml` runs the same command, so fixes must be committed first.

## Test now against Floci (your machine)
```bash
pip install -e ".[dev]" && pytest -q                       # 91 hermetic tests, no AWS or Docker needed
export DEPLOY_AGENT_EMULATOR=http://172.17.0.2:4566         # Floci endpoint from the console
deploy-agent --root /path/to/your/infra-repo plan   --stack dev-platform --spec specs/dev-platform.yaml
deploy-agent --root /path/to/your/infra-repo deploy --stack dev-platform --spec specs/dev-platform.yaml
deploy-agent audit-verify
```
1. Edit `config/stacks.yaml`: point `path` at one of your root stacks; list its input variables in `allowed_vars`.
2. First run: expect to adjust `EMULATOR_SERVICES` in `terraform.py` to your AWS provider version's endpoint names.
3. Gate negative tests: add a wildcard IAM policy / `0.0.0.0/0:22` SG to a scratch stack → `plan` must exit 3.

Note: Floci's VPC/TGW are emulated stubs on the `ec2` endpoint. That is enough to test plan, gate, apply and state; it says nothing about real routing or attachment behavior.

## GitOps leg on Floci (EKS = k3s)
```bash
aws --endpoint-url $DEPLOY_AGENT_EMULATOR eks describe-cluster --name <cluster>   # endpoint + CA; build kubeconfig from it
kubectl apply -n argocd -f <pinned argocd install manifest> && kubectl -n argocd port-forward svc/argocd-server 8443:443 &
export ARGOCD_SERVER=localhost:8443 ARGOCD_AUTH_TOKEN=<project-scoped token>
# set argocd_app in config/stacks.yaml, then:
deploy-agent deploy --stack dev-platform --spec specs/dev-platform.yaml           # applies TF, then waits Synced+Healthy
```
- The Argo repo-server inside k3s must reach your gitops repo (egress to GitHub with a read-only deploy key, or a local Gitea on the Docker network).
- Bootstrap Argo itself via Terraform (helm_release) or an app-of-apps root app, so it is covered by the same plan/gate.
- Still not real in Floci: IRSA/OIDC trust, IAM enforcement, ELB/EBS CSI behaviour. Treat those as sandbox-account tests.

Dashboard GitOps panel: set `argocd_app` for the stack in `config/stacks.yaml`, and start `deploy-agent ui` with `ARGOCD_OPTS="--core"` (uses your kubeconfig for the Floci k3s cluster, no Argo login) or `ARGOCD_SERVER` + `ARGOCD_AUTH_TOKEN`. Needs the `argocd` CLI.

## GitHub pipeline
- `ci.yml` (PR + main): pytest on py3.11-3.13, wheel build + `--version` smoke. `release.yml` (tag `vX.Y.Z`): verifies tag == version == changelog and on `main`, builds, creates the GitHub Release with `SHA256SUMS`. See CLAUDE.md > Versioning & release.
- `floci.yml` (PR/main): static checks + plan + apply of changed stacks against a **Floci** service container (no AWS account, nothing billable). `release.yml` also pushes the CLI image (root `Dockerfile`) to Docker Hub on a tag when `DOCKERHUB_USERNAME`/`DOCKERHUB_TOKEN` are set.
- Branch protection on `main`: no direct pushes; required checks `test` + `build` (ci.yml); CODEOWNERS on `config/stacks.yaml`, `modules/`.
- No real AWS in CI by design (OIDC/role-based plan+apply workflows were removed); see CLAUDE.md > No real cloud.

## Known limits / risks
- Floci validates plan/apply mechanics, state, and (EKS = k3s) the ArgoCD sync/health flow, but **not** IAM enforcement or IRSA. Use one sandbox AWS account for IAM truth.
- `tfplan` artifacts may contain secrets: private repo, 1-day retention (consider encrypting).
- Terraform has no true rollback: failures halt; recovery = revert PR + re-plan. State is never rewound automatically.
- Docker steps are tested against a fake `docker` binary in CI-less sandboxes; the first real run (Docker Desktop, hadolint, trivy output formats) is yours. Digest-pinning the base image is not automatic: the fixer pins a version tag. For this repo's own CLI image, resolve the digest with `docker buildx imagetools inspect python:3.12-slim-trixie` and pin `FROM python:3.12-slim-trixie@sha256:...`; `nightly-scan.yml` scans `main` daily for new CVEs. Dependabot ignores Python minor/major bumps: change the interpreter deliberately, with the CI matrix.
- Actions are tag-pinned in the scaffold; pin to SHAs before prod.
- Gate rules are a starter set; move to OPA/Checkov when rules outgrow Python, keep the `Decision` contract.
- ArgoCD wait requires runner→Argo reachability (self-hosted runner/tunnel) or swap for Argo notifications → `repository_dispatch`.
