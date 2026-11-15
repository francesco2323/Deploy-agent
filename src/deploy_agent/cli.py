"""deploy-agent CLI. Same entrypoints for local, Floci, and GitHub Actions.

Exit codes: 0 ok | 3 policy denied | 4 integrity/approval/account failure | 1 other
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import yaml

from .audit import Audit
from .gitops import Argo
from .runner import CmdError, run
from .spec import ENV_ORDER, SpecError, load_registry, validate_spec
from .workflow import AccountMismatch, ApprovalRequired, Deployer, IntegrityError, PolicyDenied


def _gh_output(**kv) -> None:
    p = os.environ.get("GITHUB_OUTPUT")
    if p:
        with open(p, "a") as f:
            for k, v in kv.items():
                f.write(f"{k}={v}\n")


def _parse_vars(items: list[str]) -> dict:
    out = {}
    for it in items or []:
        k, _, v = it.partition("=")
        out[k] = v
    return out


def _deployer(a, reg) -> Deployer:
    return Deployer(reg, Path(a.root), Path(a.out), Audit(Path(a.out) / "audit.jsonl"), a.tf_bin, a.emulator,
                    on_stage=lambda n: print(f"▶ {n}", file=sys.stderr, flush=True))


def _spec_from_args(a, reg):
    if a.spec:
        raw = yaml.safe_load(Path(a.spec).read_text())
    elif a.ask:
        from .llm import extract_spec
        return extract_spec(a.ask, reg)
    else:
        raw = {"stack": a.stack, "vars": _parse_vars(a.var), "allow_destroy": a.allow_destroy}
    return validate_spec(raw, reg)


def cmd_changed(a, reg) -> int:
    files = run(["git", "diff", "--name-only", f"{a.base}...HEAD"], cwd=a.root).out.split()
    hit_all = any(f.startswith(p) for f in files for p in reg.shared_paths)
    sel = [s for s in reg.stacks.values() if hit_all or any(f.startswith(s.path.rstrip("/") + "/") for f in files)]
    sel.sort(key=lambda s: (ENV_ORDER[s.env], s.name))
    matrix = [{"stack": s.name, "env": s.env, "region": s.region, "plan_role": s.plan_role,
               "apply_role": s.apply_role, "argocd_app": s.argocd_app or ""} for s in sel]
    print(json.dumps(matrix))
    _gh_output(matrix=json.dumps(matrix), any=str(bool(matrix)).lower())
    return 0


def cmd_plan(a, reg) -> int:
    spec, _ = _spec_from_args(a, reg)
    art = _deployer(a, reg).plan(spec)
    print(art.summary)
    _gh_output(verdict=art.decision.verdict)
    return 3 if art.decision.verdict == "deny" else 0


def cmd_apply(a, reg) -> int:
    res = _deployer(a, reg).apply(a.stack, approved_by=a.approved_by)
    print(json.dumps(res, indent=2))
    return 0


def cmd_deploy(a, reg) -> int:
    """Local one-shot: plan → gate → interactive approval → apply → (argocd wait)."""
    spec, stack = _spec_from_args(a, reg)
    d = _deployer(a, reg)
    art = d.plan(spec)
    print(art.summary)
    v = art.decision.verdict
    if v == "deny":
        return 3
    if v == "noop":
        print("nothing to do")
        return 0
    who = None
    if v == "needs_approval":
        if input(f"Apply plan {art.sha[:12]} to {stack.name}? [y/N] ").strip().lower() != "y":
            print("aborted")
            return 0
        who = os.environ.get("USER", "local")
    print(json.dumps(d.apply(stack.name, approved_by=who), indent=2))
    if stack.argocd_app and (not a.emulator or os.environ.get("ARGOCD_SERVER")):  # emulator: opt-in via ARGOCD_SERVER (Floci EKS = k3s)
        print(Argo().wait_healthy(stack.argocd_app))
    return 0


def cmd_ui(a, reg) -> int:
    import secrets
    import webbrowser

    from .ui import make_server

    def mk(on_stage, on_log):
        return Deployer(reg, Path(a.root), Path(a.out), Audit(Path(a.out) / "audit.jsonl"), a.tf_bin, a.emulator,
                        on_stage=on_stage, on_log=on_log)

    token = secrets.token_urlsafe(16)
    srv = make_server(reg, Path(a.root), Path(a.out), Path(a.specs), mk, token, a.port, tf_bin=a.tf_bin)
    url = f"http://127.0.0.1:{srv.server_address[1]}/?t={token}"
    print(f"dashboard: {url}   (Ctrl-C to stop)")
    if not a.no_open:
        webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def cmd_checks(a, reg) -> int:
    """Run fmt/tflint/trivy/checkov. Prints findings; emits GitHub annotations when running in Actions."""
    from .checks import ORDER, mode_for, run_check

    stack = reg.stacks[a.stack]
    sdir = Path(a.root) / stack.path
    blocked = False
    for name in ORDER:
        res = run_check(name, sdir, mode_for(stack, name), a.tf_bin)
        print(f"{res.status.upper():8} {name:8} {res.summary}")
        for f in res.findings[:30]:
            print(f"    {f['file']}:{f['line']} [{f['severity']}] {f['rule']} {f['msg']}")
            if os.environ.get("GITHUB_ACTIONS"):
                lvl = "error" if f["severity"] in ("error", "high", "critical") else "warning"
                print(f"::{lvl} file={stack.path}/{f['file']},line={f['line']},title={name} {f['rule']}::{f['msg']}")
        blocked |= res.status in ("fail", "error")
    return 3 if blocked else 0


def cmd_docker(a, reg) -> int:
    """Run the Docker pipeline headless (CI): lint -> build -> scan -> test. Local only, nothing is pushed."""
    from .dockerflow import execute_docker_pipeline, new_run
    from .pipeline import Recorder

    app = reg.apps[a.app]
    r = new_run(1, app, "ci")
    rec = Recorder(r)
    execute_docker_pipeline(r, rec, app, Path(a.root), Path(a.out), only="lint" if a.lint_only else None)
    gh = bool(os.environ.get("GITHUB_ACTIONS"))
    for j in r["jobs"]:
        for st in j["steps"]:
            print(f"{st['status'].upper():8} {j['name']}/{st['name']}")
            if st["status"] in ("failure", "warning") and st["log"]:
                print("\n".join("    " + l for l in st["log"].splitlines()[-25:]))
    if gh:
        import json as _j
        for c in _j.loads((Path(a.out) / app.name / "checks.json").read_text()):
            for f in c["findings"][:30]:
                print(f"::{'error' if f['severity'] in ('error', 'high', 'critical') else 'warning'} file={app.path}/{f['file']},line={f['line']},title={c['name']} {f['rule']}::{f['msg']}")
    print(r["error"] or "docker pipeline OK")
    return 0 if r["status"] == "success" else 3


def cmd_info(a, reg) -> int:
    print(getattr(reg.stacks[a.stack], a.field))
    return 0


def cmd_wait(a, reg) -> int:
    print(json.dumps(Argo().wait_healthy(a.app, a.revision, a.timeout)))
    return 0


def cmd_audit_verify(a, reg) -> int:
    ok = Audit.verify(Path(a.out) / "audit.jsonl")
    print("audit chain OK" if ok else "audit chain BROKEN")
    return 0 if ok else 4


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="deploy-agent")
    p.add_argument("--registry", default="config/stacks.yaml")
    p.add_argument("--root", default=".", help="repo root containing stack paths")
    p.add_argument("--out", default="out")
    p.add_argument("--tf-bin", default=os.environ.get("DEPLOY_AGENT_TF_BIN", "terraform"))
    p.add_argument("--emulator", default=os.environ.get("DEPLOY_AGENT_EMULATOR"), help="e.g. http://172.17.0.2:4566")
    sub = p.add_subparsers(dest="cmd", required=True)

    def spec_args(sp):
        sp.add_argument("--stack")
        sp.add_argument("--var", action="append")
        sp.add_argument("--allow-destroy", action="store_true")
        sp.add_argument("--spec", help="YAML spec file")
        sp.add_argument("--ask", help="natural-language request (needs [llm] extra + ANTHROPIC_API_KEY)")

    sp = sub.add_parser("changed"); sp.add_argument("--base", default="origin/main"); sp.set_defaults(fn=cmd_changed)
    sp = sub.add_parser("plan"); spec_args(sp); sp.set_defaults(fn=cmd_plan)
    sp = sub.add_parser("deploy"); spec_args(sp); sp.set_defaults(fn=cmd_deploy)
    sp = sub.add_parser("apply"); sp.add_argument("--stack", required=True); sp.add_argument("--approved-by"); sp.set_defaults(fn=cmd_apply)
    sp = sub.add_parser("ui"); sp.add_argument("--port", type=int, default=8765); sp.add_argument("--specs", default="specs"); sp.add_argument("--no-open", action="store_true"); sp.set_defaults(fn=cmd_ui)
    sp = sub.add_parser("checks"); sp.add_argument("--stack", required=True); sp.set_defaults(fn=cmd_checks)
    sp = sub.add_parser("docker"); sp.add_argument("--app", required=True); sp.add_argument("--lint-only", action="store_true"); sp.set_defaults(fn=cmd_docker)
    sp = sub.add_parser("info"); sp.add_argument("--stack", required=True); sp.add_argument("--field", required=True); sp.set_defaults(fn=cmd_info)
    sp = sub.add_parser("wait"); sp.add_argument("--app", required=True); sp.add_argument("--revision"); sp.add_argument("--timeout", type=int, default=600); sp.set_defaults(fn=cmd_wait)
    sp = sub.add_parser("audit-verify"); sp.set_defaults(fn=cmd_audit_verify)

    a = p.parse_args(argv)
    reg = load_registry(a.registry)
    try:
        return a.fn(a, reg)
    except PolicyDenied as e:
        print(f"DENIED: {e}", file=sys.stderr); return 3
    except (IntegrityError, ApprovalRequired, AccountMismatch, SpecError) as e:
        print(f"REFUSED: {type(e).__name__}: {e}", file=sys.stderr); return 4
    except CmdError as e:
        print(f"ERROR: {e}", file=sys.stderr); return 1


if __name__ == "__main__":
    sys.exit(main())
