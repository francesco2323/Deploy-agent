"""Static checks with real tools: terraform fmt, tflint, trivy config, checkov.

Each check yields a CheckResult with findings pinned to file:line (shown as annotations in the dashboard
and as GitHub annotations in CI). Mode per stack: block (failure stops the pipeline), warn (shown, never
blocks), off. Default: dev=warn, staging/prod=block. A tool that isn't installed is `skipped`, never a pass.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .runner import CmdError, run
from .spec import Stack

ORDER = ("fmt", "tflint", "trivy", "checkov")
HELP = {"fmt": "terraform", "tflint": "brew install tflint", "trivy": "brew install trivy", "checkov": "pip install checkov"}
RANK = {"critical": 4, "high": 3, "error": 3, "medium": 2, "warning": 2, "low": 1, "notice": 1, "info": 0}


@dataclass
class CheckResult:
    name: str
    status: str  # pass | warn | fail | error | skipped
    summary: str
    findings: list = field(default_factory=list)
    log: str = ""
    duration: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


def mode_for(stack: Stack, name: str) -> str:
    return stack.checks.get(name) or ("warn" if stack.env == "dev" else "block")


def _norm(p) -> str:
    p = str(p or "")
    return p[2:] if p.startswith("./") else p.lstrip("/")


def _f(file, line, sev, rule, msg) -> dict:
    return {"file": _norm(file), "line": int(line or 1), "severity": str(sev or "low").lower(), "rule": rule or "", "msg": msg or ""}


def _human(fs: list[dict]) -> str:
    return "\n".join(f"{f['file']}:{f['line']}  {f['severity']:<8} {f['rule']}  {f['msg']}" for f in fs)


def _grade(fs: list[dict], fail_at: int = 3) -> str:
    if not fs:
        return "pass"
    return "fail" if max(RANK.get(f["severity"], 1) for f in fs) >= fail_at else "warn"


def _fmt(d: Path, tf: str, rn):
    r = rn([tf, "fmt", "-check", "-diff", "-recursive", "-no-color"], cwd=d, check=False)
    if r.rc == 0:
        return "pass", "all files formatted", [], "terraform fmt -check: ok"
    if r.rc == 3:
        names = sorted({l.strip() for l in r.out.splitlines() if re.fullmatch(r"[\w./-]+\.(tf|tfvars)", l.strip())})
        fs = [_f(n, 1, "warning", "fmt", "file is not formatted (run: terraform fmt)") for n in names]
        return "fail", f"{len(names)} file(s) need formatting", fs, r.out[-8000:]
    return "error", "terraform fmt failed", [], (r.err or r.out)[-3000:]


def _tflint(d: Path, tf: str, rn):
    if (d / ".tflint.hcl").exists():
        rn(["tflint", "--init"], cwd=d, check=False, timeout=300)
    r = rn(["tflint", "--format", "json"], cwd=d, check=False)
    if r.rc not in (0, 2):
        return "error", "tflint failed", [], (r.err or r.out)[-3000:]
    doc = json.loads(r.out or "{}")
    fs = [_f(i["range"]["filename"], i["range"]["start"]["line"], i["rule"]["severity"], i["rule"]["name"], i["message"])
          for i in doc.get("issues") or []]
    if doc.get("errors"):
        return "error", f"tflint reported {len(doc['errors'])} error(s)", fs, json.dumps(doc["errors"])[:3000]
    return _grade(fs), (f"{len(fs)} issue(s)" if fs else "no issues"), fs, _human(fs) or "tflint: no issues"


def _trivy(d: Path, tf: str, rn):
    r = rn(["trivy", "config", "--format", "json", "--quiet", "--severity", "LOW,MEDIUM,HIGH,CRITICAL", "."],
           cwd=d, check=False, timeout=600)
    if r.rc != 0:
        return "error", "trivy failed", [], (r.err or r.out)[-3000:]
    doc = json.loads(r.out or "{}")
    fs = []
    for res in doc.get("Results") or []:
        for m in res.get("Misconfigurations") or []:
            cm = m.get("CauseMetadata") or {}
            fs.append(_f(res.get("Target"), cm.get("StartLine"), m.get("Severity"), m.get("AVDID") or m.get("ID"),
                         m.get("Title") or m.get("Message")))
    return _grade(fs), (f"{len(fs)} misconfiguration(s)" if fs else "no misconfigurations"), fs, _human(fs) or "trivy config: clean"


def _checkov(d: Path, tf: str, rn):
    r = rn(["checkov", "-d", ".", "--framework", "terraform", "-o", "json", "--quiet", "--compact"], cwd=d, check=False, timeout=600)
    if r.rc not in (0, 1):
        return "error", "checkov failed", [], (r.err or r.out)[-3000:]
    doc = json.loads(r.out or "{}")
    fs = []
    for dd in doc if isinstance(doc, list) else [doc]:
        for c in (dd.get("results") or {}).get("failed_checks", []):
            fs.append(_f(c.get("file_path"), (c.get("file_line_range") or [1])[0], c.get("severity") or "medium",
                         c.get("check_id"), f"{c.get('check_name', '')} ({c.get('resource', '')})"))
    return ("fail" if fs else "pass"), (f"{len(fs)} failed check(s)" if fs else "all checks passed"), fs, _human(fs) or "checkov: clean"


_CHECKS = {"fmt": _fmt, "tflint": _tflint, "trivy": _trivy, "checkov": _checkov}


def run_check(name: str, stack_dir: Path, mode: str = "warn", tf_bin: str = "terraform", run_fn=run, which=shutil.which) -> CheckResult:
    t0 = time.time()
    tool = tf_bin if name == "fmt" else name
    if mode == "off":
        return CheckResult(name, "skipped", "disabled for this stack", log=f"{name}: mode=off")
    if not which(tool):
        return CheckResult(name, "skipped", f"{tool} not installed", log=f"{tool} not found. Install: {HELP[name]}")
    try:
        status, summary, fs, log = _CHECKS[name](Path(stack_dir), tf_bin, run_fn)
    except FileNotFoundError:
        return CheckResult(name, "skipped", f"{tool} not installed", log=f"Install: {HELP[name]}")
    except (CmdError, subprocess.TimeoutExpired, ValueError, KeyError) as e:
        return CheckResult(name, "error", f"{type(e).__name__}", log=str(e)[-2000:], duration=time.time() - t0)
    if status == "fail" and mode == "warn":
        status = "warn"
    return CheckResult(name, status, summary, fs, log, round(time.time() - t0, 2))
