"""Read-only views for the dashboard sidebar: docker containers/volumes/networks and the activity log.

Only listing goes through here, plus one narrow write: removing a container THIS agent started
(name must be `deploy-agent-...`). Everything is a plain `docker ...` call through the allowlisted runner.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .audit import Audit
from .runner import CmdError, run

AGENT_PREFIX = "deploy-agent-"
_AGENT_NAME = re.compile(r"^deploy-agent-[A-Za-z0-9_.-]{1,100}$")

_CMDS = {
    "containers": ["docker", "ps", "-a", "--format", "{{json .}}"],
    "volumes": ["docker", "volume", "ls", "--format", "{{json .}}"],
    "networks": ["docker", "network", "ls", "--format", "{{json .}}"],
}


def _row(kind: str, d: dict) -> dict:
    if kind == "containers":
        name = d.get("Names", "")
        return {"id": d.get("ID", ""), "name": name, "image": d.get("Image", ""), "state": d.get("State", ""),
                "status": d.get("Status", ""), "ports": d.get("Ports", ""), "created": d.get("CreatedAt", ""),
                "agent": name.startswith(AGENT_PREFIX)}
    if kind == "volumes":
        return {"name": d.get("Name", ""), "driver": d.get("Driver", ""), "scope": d.get("Scope", "")}
    return {"id": d.get("ID", ""), "name": d.get("Name", ""), "driver": d.get("Driver", ""), "scope": d.get("Scope", "")}


def listing(kind: str, run_fn=run) -> dict:
    """`{ok, items, error}`; a missing or stopped docker is a message, never a crash."""
    if kind not in _CMDS:
        raise KeyError(kind)
    try:
        r = run_fn(_CMDS[kind], timeout=20, check=False)
    except (OSError, CmdError) as e:
        return {"ok": False, "items": [], "error": f"docker is not available: {e}"}
    if r.rc != 0:
        return {"ok": False, "items": [], "error": (r.err.strip() or "docker returned an error")[-300:]}
    items = []
    for line in r.out.splitlines():
        try:
            items.append(_row(kind, json.loads(line)))
        except ValueError:
            continue
    if kind == "containers":                       # agent-started containers first
        items.sort(key=lambda i: (not i["agent"], i["name"]))
    return {"ok": True, "items": items, "error": ""}


def is_agent_container(name: str) -> bool:
    return bool(_AGENT_NAME.fullmatch(name or ""))


def remove_container(name: str, run_fn=run) -> dict:
    if not is_agent_container(name):
        raise ValueError("only containers started by deploy-agent (name deploy-agent-...) can be removed here")
    r = run_fn(["docker", "rm", "-f", name], timeout=30, check=False)
    if r.rc != 0:
        raise RuntimeError((r.err.strip() or "docker rm failed")[-300:])
    return {"removed": name}


def _summary(data: dict) -> str:
    s = ", ".join(f"{k}={v}" for k, v in (data or {}).items())
    return s if len(s) <= 220 else s[:219] + "…"


def read_events(sources: dict[str, Path], limit: int = 300, needle: str = "") -> dict:
    """Merge hash-chained logs, newest first. `verified` is per source: True/False, None if the file does not exist yet."""
    items, verified = [], {}
    for label, path in sources.items():
        path = Path(path)
        if not path.exists():
            verified[label] = None
            continue
        try:
            verified[label] = Audit.verify(path)
        except (ValueError, KeyError, OSError):
            verified[label] = False
        for line in path.read_text().splitlines()[-2000:]:
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            items.append({"ts": rec.get("ts", 0), "source": label, "event": rec.get("event", ""),
                          "version": rec.get("version", ""), "summary": _summary(rec.get("data") or {})})
    needle = (needle or "").lower().strip()
    if needle:
        items = [i for i in items if needle in (i["event"] + " " + i["summary"] + " " + i["source"]).lower()]
    items.sort(key=lambda i: i["ts"], reverse=True)
    return {"verified": verified, "count": len(items), "items": items[:max(1, min(int(limit), 1000))]}
