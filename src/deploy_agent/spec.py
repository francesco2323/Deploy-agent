"""Typed deployment intent. The ONLY thing an LLM (or a human) may produce.

Everything downstream is deterministic. Anything not in the registry is rejected.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ENV_ORDER = {"dev": 0, "staging": 1, "prod": 2}
_SAFE = re.compile(r"^[A-Za-z0-9_./:@-]{0,128}$")


class SpecError(ValueError):
    pass


@dataclass(frozen=True)
class Stack:
    name: str
    path: str
    env: str
    account_id: str
    region: str
    plan_role: str = ""
    apply_role: str = ""
    allowed_vars: tuple[str, ...] = ()
    max_changes: int = 25
    argocd_app: str | None = None
    probes: tuple[str, ...] = ()
    checks: dict = field(default_factory=dict)


@dataclass(frozen=True)
class App:
    """A container app built and tested locally (Docker). Path is relative to --root."""
    name: str
    path: str
    image: str = ""
    port: int = 8080
    health_path: str = "/healthz"
    checks: dict = field(default_factory=dict)  # captain|hadolint|trivy|vulns: block|warn|off


@dataclass(frozen=True)
class DeploySpec:
    stack: str
    vars: dict = field(default_factory=dict)
    allow_destroy: bool = False

    def to_dict(self) -> dict:
        return {"stack": self.stack, "vars": dict(self.vars), "allow_destroy": self.allow_destroy}

    def hash(self) -> str:
        return hashlib.sha256(json.dumps(self.to_dict(), sort_keys=True).encode()).hexdigest()


@dataclass(frozen=True)
class Registry:
    stacks: dict[str, Stack]
    shared_paths: tuple[str, ...] = ()
    apps: dict[str, App] = field(default_factory=dict)


APP_CHECKS = ("captain", "hadolint", "trivy", "vulns")


def _checks(name: str, raw: dict) -> dict:
    bad = {k: v for k, v in raw.items() if v not in ("block", "warn", "off")}
    if bad:
        raise SpecError(f"{name}: checks modes must be block|warn|off, got {bad}")
    return dict(raw)


def load_registry(path: str | Path) -> Registry:
    raw = yaml.safe_load(Path(path).read_text())
    stacks = {}
    for name, s in (raw.get("stacks") or {}).items():
        if s["env"] not in ENV_ORDER:
            raise SpecError(f"{name}: env must be one of {list(ENV_ORDER)}")
        stacks[name] = Stack(
            name=name,
            path=s["path"],
            env=s["env"],
            account_id=str(s["account_id"]),
            region=s["region"],
            plan_role=s.get("plan_role", ""),
            apply_role=s.get("apply_role", ""),
            allowed_vars=tuple(s.get("allowed_vars", [])),
            max_changes=int(s.get("max_changes", 25)),
            argocd_app=s.get("argocd_app"),
            probes=tuple(s.get("probes", [])),
            checks=_checks(name, s.get("checks") or {}),
        )
    apps = {}
    for name, a in (raw.get("apps") or {}).items():
        modes = a.get("checks") or {}
        bad = {k: v for k, v in modes.items() if k not in APP_CHECKS or v not in ("block", "warn", "off")}
        if bad:
            raise SpecError(f"app {name}: checks must be {APP_CHECKS} with block|warn|off, got {bad}")
        apps[name] = App(name=name, path=a["path"], image=a.get("image") or f"deploy-agent/{name}",
                         port=int(a.get("port", 8080)), health_path=a.get("health_path", "/healthz"), checks=modes)
    return Registry(stacks, tuple(raw.get("shared_paths", [])), apps)


def validate_spec(raw: dict, registry: Registry) -> tuple[DeploySpec, Stack]:
    name = raw.get("stack")
    if name not in registry.stacks:
        raise SpecError(f"unknown stack: {name!r}")
    stack = registry.stacks[name]
    vars_ = raw.get("vars") or {}
    if not isinstance(vars_, dict):
        raise SpecError("vars must be a mapping")
    for k, v in vars_.items():
        if k not in stack.allowed_vars:
            raise SpecError(f"variable {k!r} not allowed for stack {name}")
        if isinstance(v, bool) or isinstance(v, int):
            continue
        if not isinstance(v, str) or not _SAFE.match(v):
            raise SpecError(f"variable {k!r}: value rejected (type/charset)")
    allow_destroy = bool(raw.get("allow_destroy", False))
    if allow_destroy and stack.env == "prod":
        raise SpecError("allow_destroy is never permitted for prod")
    return DeploySpec(name, dict(vars_), allow_destroy), stack
