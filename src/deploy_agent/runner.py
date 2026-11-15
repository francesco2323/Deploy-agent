"""Single choke point for subprocess execution: allowlisted binaries, no shell, scrubbed env."""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass

ALLOWED = {"terraform", "tofu", "argocd", "git", "gh", "aws", "tflint", "trivy", "checkov", "docker", "hadolint"}
_PASS_KEYS = {"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SSH_AUTH_SOCK"}
_PASS_PREFIXES = ("AWS_", "TF_", "ARGOCD_", "GH_", "GITHUB_", "DOCKER_", "BUILDKIT_")
_MAX = 200_000


class CmdError(RuntimeError):
    pass


@dataclass
class Result:
    rc: int
    out: str
    err: str


def run(argv: list[str], cwd=None, env: dict | None = None, timeout: int = 1800, check: bool = True) -> Result:
    name = os.path.basename(argv[0])
    if name not in ALLOWED:
        raise CmdError(f"binary not allowlisted: {name}")
    base = {k: v for k, v in os.environ.items() if k in _PASS_KEYS or k.startswith(_PASS_PREFIXES)}
    base.update(env or {})
    p = subprocess.run(argv, cwd=cwd, env=base, capture_output=True, text=True, timeout=timeout, shell=False)
    res = Result(p.returncode, p.stdout[-_MAX:] if len(p.stdout) > _MAX else p.stdout, p.stderr[-_MAX:])
    if check and res.rc != 0:
        raise CmdError(f"{name} {argv[1] if len(argv) > 1 else ''} failed rc={res.rc}: {res.err.strip()[-2000:]}")
    return res
