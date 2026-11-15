"""One-click remediation.

A Fix is computed by the SERVER from the files as they are right now (never from client input), shown as a diff,
and only written when the user clicks Apply. Writes are limited to the target's own folder under --root, are
compare-and-swap (the file must still equal `before`), are recorded for Undo, and are never committed.
Anything without a safe deterministic fix is reported as manual instead of guessed.
"""
from __future__ import annotations

import difflib
import json
import re
import shutil
import tempfile
import time
from pathlib import Path

from . import dockerfile as df
from .runner import run

TF_FILES = (".tf", ".tfvars")
PAB = {"AVD-AWS-0086", "AVD-AWS-0087", "AVD-AWS-0091", "AVD-AWS-0093", "AVD-AWS-0094", "CKV2_AWS_6", "CKV_AWS_53", "CKV_AWS_54", "CKV_AWS_55", "CKV_AWS_56"}
VER = {"AVD-AWS-0090", "CKV_AWS_21"}
SSE = {"AVD-AWS-0088", "CKV_AWS_19"}
REQ = {"terraform_required_version"}


class FixError(Exception):
    pass


def _diff(path: str, before: str | None, after: str) -> str:
    a = (before or "").splitlines(keepends=True)
    b = after.splitlines(keepends=True)
    return "".join(difflib.unified_diff(a, b, f"a/{path}" if before is not None else "/dev/null", f"b/{path}", n=2))


def make_fix(fid, target, check, title, why, resolves, files, **extra) -> dict:
    return {"id": fid, "target": target, "check": check, "title": title, "why": why, "resolves": sorted(resolves),
            "files": [{"path": p, "before": b, "after": a, "diff": _diff(p, b, a)} for p, b, a in files], "auto": True, **extra}


def _read(p: Path) -> str:
    return p.read_text(errors="replace")


# ------------------------------------------------------------------ terraform
def _blocks(text: str):
    for m in re.finditer(r'^resource\s+"([\w-]+)"\s+"([\w-]+)"\s*\{', text, re.M):
        depth, i = 1, m.end()
        while i < len(text) and depth:
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        yield m.group(1), m.group(2), text[m.start():i]


def _rules(results: list[dict], check: str | None = None) -> set[str]:
    return {f["rule"] for c in results if check in (None, c["name"]) for f in c.get("findings", [])}


def tf_fixes(stack, root: Path, results: list[dict], run_fn=run, tf_bin="terraform") -> tuple[list[dict], list[dict]]:
    """-> (fixes, manual). results = last checks.json."""
    sdir = Path(root) / stack.path
    rel = lambda p: p.relative_to(root).as_posix()
    fixes, covered = [], set()
    by_name = {c["name"]: c for c in results}

    fmt = by_name.get("fmt")
    if fmt and fmt["findings"]:
        with tempfile.TemporaryDirectory() as td:
            dst = Path(td) / "s"
            shutil.copytree(sdir, dst, ignore=shutil.ignore_patterns(".terraform", ".git", "*.tfstate*"))
            run_fn([tf_bin, "fmt", "-recursive", "-no-color"], cwd=dst, check=False)
            files = []
            for p in sorted(sdir.rglob("*")):
                if p.suffix in TF_FILES and ".terraform" not in p.parts and p.is_file():
                    q = dst / p.relative_to(sdir)
                    if q.exists() and _read(q) != _read(p):
                        files.append((rel(p), _read(p), _read(q)))
        if files:
            fixes.append(make_fix("tf-fmt", "tf", "fmt", "Format Terraform files (terraform fmt)",
                                  "Terraform has one official layout for spacing and alignment. Formatting only changes whitespace, never what the code does, and keeps diffs small and reviews easy.",
                                  {"fmt"}, files))
            covered.add("fmt")

    rules = _rules(results)
    tfs = [p for p in sorted(sdir.rglob("*.tf")) if ".terraform" not in p.parts]
    texts = {p: _read(p) for p in tfs}
    allblocks = [(p, t, n, b) for p, tx in texts.items() for t, n, b in _blocks(tx)]
    for p, t, n, b in allblocks:
        if t != "aws_s3_bucket":
            continue
        ref = f"aws_s3_bucket.{n}."
        have = {t2 for _, t2, _, b2 in allblocks if ref in b2}
        for fid, ids, rtype, title, why, body in (
            ("pab", PAB, "aws_s3_bucket_public_access_block", "Block all public access",
             "A bucket can be made public by a single wrong ACL or policy. This switch overrides all of them, so data cannot be exposed by accident.",
             '  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n'),
            ("versioning", VER, "aws_s3_bucket_versioning", "Turn on versioning",
             "Keeps every previous version of every object, so an accidental overwrite or delete can be undone.",
             '  versioning_configuration {\n    status = "Enabled"\n  }\n'),
            ("sse", SSE, "aws_s3_bucket_server_side_encryption_configuration", "Encrypt objects at rest",
             "Objects are encrypted on disk with AES-256. No change for the app; protects data if storage is ever exposed.",
             '  rule {\n    apply_server_side_encryption_by_default {\n      sse_algorithm = "AES256"\n    }\n  }\n'),
        ):
            hit = rules & ids
            if not hit or rtype in have:
                continue
            snippet = f'\nresource "{rtype}" "{n}" {{\n  bucket = aws_s3_bucket.{n}.id\n{body}}}\n'
            fixes.append(make_fix(f"s3-{fid}-{n}", "tf", "trivy/checkov", f"{title}: aws_s3_bucket.{n}", why, hit,
                                  [(rel(p), texts[p], texts[p].rstrip("\n") + "\n" + snippet)]))
            covered |= hit

    if rules & REQ and not any(re.search(r"required_version\s*=", tx) for tx in texts.values()):
        for p, tx in texts.items():
            m = re.search(r"^terraform\s*\{[^\n]*\n", tx, re.M)
            if m:
                new = tx[:m.end()] + '  required_version = ">= 1.5.0"\n' + tx[m.end():]
                fixes.append(make_fix("tf-required-version", "tf", "tflint", "Declare the minimum Terraform version",
                                      "Without required_version, someone with an old Terraform can run this code and corrupt the state. This makes old versions refuse to run it.",
                                      REQ & rules, [(rel(p), tx, new)]))
                covered |= REQ
                break

    manual = _manual(results, covered, {"fmt"})
    return fixes, manual


def _manual(results: list[dict], covered: set[str], skip: set[str]) -> list[dict]:
    out = []
    for c in results:
        if c["name"] in skip and c["name"] in covered:
            continue
        for f in c.get("findings", []):
            if f["rule"] in covered or (c["name"] == "fmt" and "fmt" in covered):
                continue
            out.append({"check": c["name"], "file": f["file"], "line": f["line"], "severity": f["severity"], "rule": f["rule"], "msg": f["msg"]})
    return out


# ------------------------------------------------------------------ docker
def docker_fixes(app, root: Path, results: list[dict]) -> tuple[list[dict], list[dict]]:
    adir = Path(root) / app.path
    dpath = adir / "Dockerfile"
    if not dpath.exists():
        return [], []
    text = _read(dpath)
    ignore_exists = (adir / ".dockerignore").exists()
    lint = df.lint(text, ignore_exists)
    rules = {f["rule"] for f in lint} | _rules(results)
    ctx = {"port": app.port, "health_path": app.health_path, "name": app.name}
    rel = lambda p: p.relative_to(root).as_posix()
    fixes, covered = [], set()
    for fid, ids, title, why, fn in df.FIXES:
        hit = rules & set(ids)
        if not hit:
            continue
        new = fn(text, ctx)
        if new and new != text:
            fixes.append(make_fix(f"docker-{fid}", "docker", "captain", title, why, hit, [(rel(dpath), text, new)]))
            covered |= hit
    if not ignore_exists and "CAP004" in rules:
        fid, ids, title, why, _ = df.DOCKERIGNORE
        fixes.append(make_fix("docker-dockerignore", "docker", "captain", title, why, set(ids),
                              [(rel(adir / ".dockerignore"), None, df.IGNORE)]))
        covered |= set(ids)
    fid, ids, title, why, fn = df.MULTISTAGE
    if "CAP008" in rules and not any(f["id"] != "docker-dockerignore" for f in fixes):
        new = fn(text, ctx)
        if new and new != text:
            fixes.append(make_fix("docker-multi-stage", "docker", "captain", title, why, set(ids), [(rel(dpath), text, new)]))
            covered |= set(ids)
    if "CAP008" in rules and fid == "multi-stage" and fn(text, ctx):
        covered |= {"CAP008"}  # offered as soon as the basics above are fixed
    # tool findings not covered by any fix (hadolint/trivy ids we do not know) stay manual
    manual = [{"check": f.get("tool", "captain"), "file": f["file"], "line": f["line"], "severity": f["severity"], "rule": f["rule"], "msg": f["msg"]}
              for f in lint if f["rule"] not in covered]
    return fixes, manual


# ------------------------------------------------------------------ apply / undo
def _safe(root: Path, base: str, rel: str) -> Path:
    p = (Path(root) / rel).resolve()
    b = (Path(root) / base).resolve()
    if not p.is_relative_to(b):
        raise FixError(f"refusing to write outside {base}")
    if any(part.startswith(".") and part not in (".dockerignore",) for part in p.relative_to(b).parts):
        raise FixError("refusing to write to a hidden path")
    return p


def apply_fix(root: Path, base: str, fix: dict, store: Path) -> list[str]:
    plan = []
    for f in fix["files"]:
        p = _safe(root, base, f["path"])
        cur = _read(p) if p.exists() else None
        if cur != f["before"]:
            raise FixError(f"{f['path']} changed since the fix was computed; refresh and try again")
        plan.append((p, f))
    for p, f in plan:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(p.name + ".fix-tmp")
        tmp.write_text(f["after"])
        tmp.replace(p)
    hist = _hist(store)
    hist.append({"id": fix["id"], "title": fix["title"], "at": time.time(), "base": base,
                 "files": [{"path": f["path"], "before": f["before"], "after": f["after"]} for f in fix["files"]]})
    _save(store, hist)
    return [f["path"] for f in fix["files"]]


def undo_last(root: Path, store: Path) -> dict:
    hist = _hist(store)
    if not hist:
        raise FixError("nothing to undo")
    e = hist[-1]
    for f in e["files"]:
        p = _safe(root, e["base"], f["path"])
        cur = _read(p) if p.exists() else None
        if cur != f["after"]:
            raise FixError(f"{f['path']} was edited after the fix; not overwriting it")
    for f in e["files"]:
        p = _safe(root, e["base"], f["path"])
        if f["before"] is None:
            p.unlink(missing_ok=True)
        else:
            p.write_text(f["before"])
    hist.pop()
    _save(store, hist)
    return {"undone": e["title"]}


def _hist(store: Path) -> list:
    try:
        return json.loads(Path(store).read_text())
    except (OSError, ValueError):
        return []


def _save(store: Path, hist: list) -> None:
    Path(store).parent.mkdir(parents=True, exist_ok=True)
    Path(store).write_text(json.dumps(hist))


def history(store: Path) -> list[dict]:
    return [{"id": h["id"], "title": h["title"], "at": h["at"]} for h in _hist(store)]
