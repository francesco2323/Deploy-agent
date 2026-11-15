"""Deterministic deploy state machine.

plan phase : validate spec → init/validate → plan(-out) → gate → persist {spec, meta, decision, summary}
apply phase: re-verify integrity → re-run gate on the plan itself → approval check → apply saved plan

The apply phase trusts nothing from the plan phase except the hash-pinned plan file.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from .audit import Audit
from .gate import Decision, evaluate, render_summary
from .runner import CmdError, run
from .spec import DeploySpec, Registry, Stack, validate_spec
from .terraform import Terraform, file_sha


class IntegrityError(RuntimeError): ...
class PolicyDenied(RuntimeError): ...
class ApprovalRequired(RuntimeError): ...
class AccountMismatch(RuntimeError): ...


@dataclass
class PlanArtifact:
    stack: Stack
    out_dir: Path
    sha: str
    decision: Decision
    summary: str


class Deployer:
    def __init__(self, registry: Registry, root: Path, out_root: Path, audit: Audit, tf_bin: str = "terraform",
                 emulator: str | None = None, run_fn=run, on_stage=None, on_log=None):
        self.reg, self.root, self.out_root, self.audit = registry, Path(root), Path(out_root), audit
        self.tf_bin, self.emulator, self._run = tf_bin, emulator, run_fn
        self._on_stage = on_stage or (lambda n: None)
        self._on_log = on_log

    # -- helpers
    def _stage(self, stack: Stack, name: str) -> None:
        self.audit.log("stage", stack=stack.name, name=name)
        self._on_stage(name)

    def _tf(self, stack: Stack) -> Terraform:
        if not (self.root / stack.path).is_dir():
            raise CmdError(f"stack dir not found: {self.root / stack.path} (check --root and 'path' in the registry)")
        return Terraform(self.root / stack.path, self.out_root / stack.name, self.tf_bin, self.emulator,
                         stack.region, self._run, self._on_log)

    def _git_sha(self, stack: Stack) -> str:
        if os.environ.get("GITHUB_SHA"):
            return os.environ["GITHUB_SHA"]
        r = self._run(["git", "-C", str(self.root / stack.path), "rev-parse", "HEAD"], check=False)
        return r.out.strip() if r.rc == 0 else ""

    def _guard_account(self, stack: Stack) -> None:
        if self.emulator:
            return
        r = self._run(["aws", "sts", "get-caller-identity", "--query", "Account", "--output", "text"])
        if r.out.strip() != stack.account_id:
            raise AccountMismatch(f"credentials are for account {r.out.strip()}, stack {stack.name} expects {stack.account_id}")

    # -- phases
    def plan(self, spec: DeploySpec) -> PlanArtifact:
        stack = self.reg.stacks[spec.stack]
        out = self.out_root / stack.name
        out.mkdir(parents=True, exist_ok=True)
        self._guard_account(stack)
        tf = self._tf(stack)
        self._stage(stack, "init")
        tf.init()
        self._stage(stack, "validate")
        tf.validate()
        self._stage(stack, "plan")
        pr = tf.plan(spec.vars)
        self._stage(stack, "gate")
        dec = evaluate(pr.plan, stack, spec)
        summary = render_summary(stack, pr.plan, dec, pr.sha)
        meta = {"stack": stack.name, "plan_sha": pr.sha, "spec_hash": spec.hash(), "git_sha": self._git_sha(stack)}
        (out / "spec.json").write_text(json.dumps(spec.to_dict()))
        (out / "meta.json").write_text(json.dumps(meta))
        (out / "decision.json").write_text(json.dumps(dec.to_dict(), indent=2))
        (out / "summary.md").write_text(summary)
        self.audit.log("plan", stack=stack.name, verdict=dec.verdict, plan_sha=pr.sha, counts=dec.counts,
                       findings=[f.rule for f in dec.findings])
        return PlanArtifact(stack, out, pr.sha, dec, summary)

    def apply(self, stack_name: str, approved_by: str | None = None) -> dict:
        stack = self.reg.stacks[stack_name]
        out = self.out_root / stack.name
        meta = json.loads((out / "meta.json").read_text())
        spec, _ = validate_spec(json.loads((out / "spec.json").read_text()), self.reg)
        tf = self._tf(stack)

        self._stage(stack, "verify")
        if file_sha(tf.plan_path) != meta["plan_sha"]:
            raise IntegrityError("plan file hash changed since plan phase")
        if spec.hash() != meta["spec_hash"]:
            raise IntegrityError("spec changed since plan phase")
        cur = self._git_sha(stack)
        if meta["git_sha"] and cur and cur != meta["git_sha"]:
            raise IntegrityError(f"plan built from {meta['git_sha'][:8]}, now at {cur[:8]}")

        self._guard_account(stack)
        tf.init()
        self._stage(stack, "regate")
        dec = evaluate(tf.show(tf.plan_path), stack, spec)  # never trust decision.json
        if dec.verdict == "deny":
            self.audit.log("apply_denied", stack=stack.name, findings=[f.rule for f in dec.findings])
            raise PolicyDenied("; ".join(f"{f.rule}@{f.address}" for f in dec.findings if f.severity == "deny"))
        if dec.verdict == "noop":
            self.audit.log("apply_noop", stack=stack.name)
            return {"status": "noop"}
        if dec.verdict == "needs_approval" and not approved_by:
            raise ApprovalRequired(f"{stack.name} requires approval (env={stack.env})")

        self.audit.log("apply_start", stack=stack.name, plan_sha=meta["plan_sha"], approved_by=approved_by or "auto-dev")
        self._stage(stack, "apply")
        tf.apply(tf.plan_path)
        outs = {k: v.get("value") for k, v in tf.outputs().items() if not v.get("sensitive")}
        self.audit.log("apply_done", stack=stack.name, plan_sha=meta["plan_sha"])
        return {"status": "applied", "outputs": outs}
