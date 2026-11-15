"""GitOps leg. The agent never writes to the cluster: it proposes a commit/PR to the gitops repo
and observes ArgoCD. Merge policy (branch protection/CODEOWNERS) is the approval control.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import yaml

from .runner import CmdError, run


def set_values(values_file: Path, updates: dict, allowed_keys: set[str]) -> None:
    bad = set(updates) - allowed_keys
    if bad:
        raise CmdError(f"gitops keys not allowed: {sorted(bad)}")
    doc = yaml.safe_load(values_file.read_text()) or {}
    for dotted, val in updates.items():
        node, *path = [doc] + dotted.split(".")
        for p in path[:-1]:
            node = node.setdefault(p, {})
        node[path[-1]] = val
    values_file.write_text(yaml.safe_dump(doc, sort_keys=False))


class GitOps:
    def __init__(self, repo: Path, run_fn=run):
        self.repo, self._run = Path(repo), run_fn

    def _git(self, *a, check=True):
        return self._run(["git", "-C", str(self.repo), *a], check=check)

    def propose(self, values_rel: str, updates: dict, allowed: set[str], branch: str, title: str, open_pr: bool = True) -> str:
        self._git("checkout", "-B", branch)
        set_values(self.repo / values_rel, updates, allowed)
        self._git("add", values_rel)
        self._git("commit", "-m", title)
        sha = self._git("rev-parse", "HEAD").out.strip()
        self._git("push", "--force-with-lease", "origin", branch)
        if open_pr:
            self._run(["gh", "pr", "create", "--fill", "--head", branch], cwd=self.repo, check=False)
        return sha

    def revert_proposal(self, bad_sha: str, branch: str) -> str:
        self._git("checkout", "-B", branch)
        self._git("revert", "--no-edit", bad_sha)
        self._git("push", "--force-with-lease", "origin", branch)
        self._run(["gh", "pr", "create", "--fill", "--head", branch, "--label", "rollback"], cwd=self.repo, check=False)
        return self._git("rev-parse", "HEAD").out.strip()


class Argo:
    def __init__(self, run_fn=run):
        self._run = run_fn

    def status(self, app: str) -> dict:
        d = json.loads(self._run(["argocd", "app", "get", app, "-o", "json"]).out)
        st = d.get("status", {})
        return {"sync": st.get("sync", {}).get("status"), "rev": st.get("sync", {}).get("revision"),
                "health": st.get("health", {}).get("status")}

    def detail(self, app: str) -> dict:
        d = json.loads(self._run(["argocd", "app", "get", app, "-o", "json"]).out)
        sp, st = d.get("spec", {}), d.get("status", {})
        src = sp.get("source") or (sp.get("sources") or [{}])[0]
        dest = sp.get("destination", {})
        op = st.get("operationState") or {}
        return {
            "app": app,
            "sync": st.get("sync", {}).get("status"),
            "revision": st.get("sync", {}).get("revision"),
            "health": st.get("health", {}).get("status"),
            "repo": src.get("repoURL"), "path": src.get("path"), "target": src.get("targetRevision"),
            "namespace": dest.get("namespace"), "cluster": dest.get("name") or dest.get("server"),
            "operation": {"phase": op.get("phase"), "message": op.get("message"), "finished": op.get("finishedAt")} if op else None,
            "resources": [{"kind": r.get("kind"), "name": r.get("name"), "namespace": r.get("namespace"),
                           "sync": r.get("status"), "health": (r.get("health") or {}).get("status"),
                           "message": (r.get("health") or {}).get("message", "")} for r in st.get("resources", [])],
            "conditions": [{"type": c.get("type"), "message": c.get("message")} for c in st.get("conditions", [])],
            "history": [{"id": h.get("id"), "revision": h.get("revision"), "deployed": h.get("deployedAt")}
                        for h in st.get("history", [])][-5:][::-1],
        }

    def wait_healthy(self, app: str, revision: str | None = None, timeout: int = 600, poll: int = 10) -> dict:
        end = time.time() + timeout
        s: dict = {}
        while time.time() < end:
            s = self.status(app)
            if s["health"] == "Degraded":
                raise CmdError(f"{app} Degraded: {s}")
            if s["sync"] == "Synced" and s["health"] == "Healthy" and (revision is None or s["rev"] == revision):
                return s
            time.sleep(poll)
        raise CmdError(f"{app} not Healthy/Synced within {timeout}s: {s}")
