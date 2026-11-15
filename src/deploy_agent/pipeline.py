"""GitHub-Actions-style run model: a run has jobs, jobs have steps, steps have logs and durations.

checks (fmt, tflint, trivy, checkov) -> plan (init, validate, plan) -> gate -> apply (verify, regate, apply, argocd)
Blocking check failures and gate denials skip everything downstream. Apply waits for an explicit approval.
"""
from __future__ import annotations

import json
import shutil
import threading
import time
from pathlib import Path

from .checks import ORDER, mode_for, run_check
from .runner import run
from .spec import DeploySpec, Stack

LOCK = threading.RLock()
STEP_STATUS = {"pass": "success", "warn": "warning", "fail": "failure", "error": "failure", "skipped": "skipped"}
_LOG_CAP = 60_000


def skeleton(stack: Stack) -> list[dict]:
    apply_steps = [("verify", "Verify plan integrity"), ("regate", "Re-run policy gate"), ("apply", "terraform apply")]
    if stack.argocd_app:
        apply_steps.append(("argocd", "Wait for ArgoCD Synced + Healthy"))
    spec = [
        ("checks", "Static checks", [("fmt", "terraform fmt"), ("tflint", "tflint"), ("trivy", "trivy config"), ("checkov", "checkov")]),
        ("plan", "Terraform plan", [("init", "terraform init"), ("validate", "terraform validate"), ("plan", "terraform plan")]),
        ("gate", "Policy gate", [("gate", "Evaluate plan")]),
        ("apply", "Apply", apply_steps),
    ]
    return [{"name": n, "title": t, "status": "pending", "started": None, "ended": None,
             "steps": [{"name": sn, "title": st, "status": "pending", "started": None, "ended": None, "log": ""} for sn, st in steps]}
            for n, t, steps in spec]


def new_run(rid: int, stack: Stack, ref: str) -> dict:
    return {"id": rid, "stack": stack.name, "env": stack.env, "status": "running", "started": time.time(), "ended": None,
            "ref": ref, "verdict": None, "plan_sha": None, "counts": None, "error": None, "jobs": skeleton(stack)}


def snapshot(run_: dict | None) -> dict | None:
    with LOCK:
        return json.loads(json.dumps(run_)) if run_ else None


class Recorder:
    def __init__(self, run_: dict):
        self.run, self.cur = run_, None

    def _find(self, name: str):
        for j in self.run["jobs"]:
            for s in j["steps"]:
                if s["name"] == name:
                    return j, s
        raise KeyError(name)

    def start(self, name: str) -> None:
        with LOCK:
            try:
                j, s = self._find(name)
            except KeyError:
                return
            if self.cur:
                cj = self.cur[0]
                self.finish("success")
                if cj is not j:
                    self._close_job(cj, "success")
            s.update(status="running", started=time.time())
            if j["status"] in ("pending", "waiting"):
                j.update(status="running", started=time.time())
            self.cur = (j, s)

    on_stage = start

    def log(self, text: str) -> None:
        with LOCK:
            if self.cur:
                s = self.cur[1]
                s["log"] = (s["log"] + text)[-_LOG_CAP:]

    def finish(self, status: str = "success", note: str = "") -> None:
        with LOCK:
            if self.cur:
                s = self.cur[1]
                if note:
                    s["log"] = (s["log"] + ("\n" if s["log"] else "") + note)[-_LOG_CAP:]
                s.update(status=status, ended=time.time())
                self.cur = None

    def _close_job(self, j: dict, status: str) -> None:
        j.update(status=status, ended=time.time())

    def end_job(self, name: str, status: str) -> None:
        with LOCK:
            if self.cur and self.cur[0]["name"] == name:
                self.finish("success")
            j = next(j for j in self.run["jobs"] if j["name"] == name)
            self._close_job(j, status)

    def _skip_pending(self) -> None:
        for j in self.run["jobs"]:
            for s in j["steps"]:
                if s["status"] == "pending":
                    s["status"] = "skipped"
            if j["status"] == "pending":
                j["status"] = "skipped"

    def fail(self, msg: str) -> None:
        with LOCK:
            if self.cur:
                j = self.cur[0]
                self.finish("failure", note=msg)
                self._close_job(j, "failure")
            self._skip_pending()
            self.run.update(status="failure", error=msg, ended=time.time())


def _gate_text(dec) -> str:
    c = dec.counts
    lines = [f"verdict: {dec.verdict.upper()}", f"changes: +{c.get('create', 0)} ~{c.get('update', 0)} -{c.get('delete', 0)} replace {c.get('replace', 0)}"]
    if dec.findings:
        lines.append("findings:")
        lines += [f"  {f.severity:<4}  {f.rule}  {f.address}  {f.msg}" for f in dec.findings]
    else:
        lines.append("findings: none")
    return "\n".join(lines)


def execute_pipeline(run_: dict, rec: Recorder, stack: Stack, spec: DeploySpec, make_deployer, root: Path, out_root: Path,
                     tf_bin: str = "terraform", run_fn=run, which=shutil.which, only: str | None = None) -> None:
    sdir = Path(root) / stack.path
    results, blocked = [], False
    for name in ORDER:
        rec.start(name)
        res = run_check(name, sdir, mode_for(stack, name), tf_bin, run_fn, which)
        results.append(res.to_dict())
        rec.log(f"{res.log}\n\n{res.summary}")
        rec.finish(STEP_STATUS[res.status])
        blocked |= res.status in ("fail", "error")
    out = Path(out_root) / stack.name
    out.mkdir(parents=True, exist_ok=True)
    (out / "checks.json").write_text(json.dumps(results))
    rec.end_job("checks", "failure" if blocked else "success")
    if blocked:
        rec.fail("Blocking static check failed. Fix the findings (or set the check to warn in config/stacks.yaml).")
        return
    if only == "checks":
        rec._skip_pending()
        with LOCK:
            run_.update(status="success", ended=time.time())
        return

    art = make_deployer(rec.on_stage, rec.log).plan(spec)
    dec = art.decision
    with LOCK:
        run_.update(verdict=dec.verdict, plan_sha=art.sha, counts=dec.counts)
    rec.log(_gate_text(dec))
    if dec.verdict == "deny":
        rec.finish("failure")
        rec.end_job("gate", "failure")
        rec.fail("Policy gate denied: " + ", ".join(sorted({f.rule for f in dec.findings if f.severity == "deny"})))
        return
    rec.finish("success")
    rec.end_job("gate", "success")
    with LOCK:
        aj = next(j for j in run_["jobs"] if j["name"] == "apply")
        if dec.verdict == "noop":
            aj["status"] = "skipped"
            for s in aj["steps"]:
                s["status"] = "skipped"
            run_.update(status="success", ended=time.time())
        else:
            aj["status"] = "waiting"
            run_["status"] = "waiting"


def execute_apply(run_: dict, rec: Recorder, stack: Stack, make_deployer, argo=None) -> None:
    res = make_deployer(rec.on_stage, rec.log).apply(stack.name, approved_by="ui")
    if stack.argocd_app and argo and res.get("status") == "applied":
        rec.start("argocd")
        out = argo.wait_healthy(stack.argocd_app, timeout=600)
        rec.log(json.dumps(out, indent=2))
    else:
        rec.log(json.dumps(res, indent=2))
    rec.finish("success")
    rec.end_job("apply", "success")
    with LOCK:
        run_.update(status="success", ended=time.time())
