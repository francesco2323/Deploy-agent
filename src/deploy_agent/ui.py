"""Local dashboard styled like a GitHub Actions run page.

Matrix of stacks, job graph (checks -> plan -> gate -> apply), collapsible per-step logs, the Terraform folder
tree with findings pinned to files/lines, and an approval box. Read-mostly: it runs the same Deployer the CLI and
CI use. Binds 127.0.0.1 only, per-run token, Host-header check, one run at a time, Apply needs the plan-hash prefix.
Real approval in CI stays in GitHub Environments.
"""
from __future__ import annotations

import json
import shutil
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import yaml

from . import dockerfile as dfile
from . import dockerflow, remediate
from .gitops import Argo
from .pipeline import Recorder, execute_apply, execute_pipeline, new_run, skeleton, snapshot
from .runner import run
from .spec import validate_spec

SKIP_DIRS = {".git", ".terraform", "node_modules", "__pycache__", ".venv", "out", ".idea", ".vscode"}
KEEP_DOT = {".tflint.hcl", ".terraform.lock.hcl", ".trivyignore", ".dockerignore", "Dockerfile"}
EXTS = {".tf", ".tfvars", ".hcl", ".md", ".yaml", ".yml", ".trivyignore", ".py", ".txt"}
MAX_NODES, MAX_FILE = 600, 200_000


def _jload(p: Path):
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return None


def build_tree(root: Path, stack_path: str, findings: dict[str, list], changed: set[str]) -> dict:
    count = [0]

    def walk(d: Path, rel: str):
        node = {"name": d.name or "repo", "type": "dir", "path": rel, "children": []}
        try:
            entries = sorted(d.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
        except OSError:
            return node
        for p in entries:
            if count[0] > MAX_NODES:
                break
            if p.name in SKIP_DIRS or (p.name.startswith(".") and p.name not in KEEP_DOT) or p.is_symlink():
                continue
            prel = f"{rel}/{p.name}" if rel else p.name
            if p.is_dir():
                child = walk(p, prel)
                if child["children"]:
                    node["children"].append(child)
            elif p.suffix in EXTS or p.name in KEEP_DOT:
                count[0] += 1
                fs = findings.get(prel, [])
                node["children"].append({"name": p.name, "type": "file", "path": prel, "findings": len(fs),
                                         "worst": max((f["rank"] for f in fs), default=0), "changed": prel in changed})
        return node

    return {"stack": stack_path, "root": walk(root, "")}


def _changed(root: Path) -> set[str]:
    r = run(["git", "-C", str(root), "status", "--porcelain"], check=False)
    return {line[3:].strip().strip('"') for line in r.out.splitlines() if len(line) > 3} if r.rc == 0 else set()


def make_server(reg, root: Path, out_root: Path, specs_dir: Path, make_deployer, token: str, port: int = 0,
                argo=None, tf_bin: str = "terraform", check_run=None, which=None) -> ThreadingHTTPServer:
    from .checks import RANK
    argo = argo or Argo()
    root, out_root, specs_dir = Path(root).resolve(), Path(out_root), Path(specs_dir)
    runs: dict[str, dict] = {}
    state = {"counter": 0}
    lock = threading.Lock()

    def busy() -> bool:
        return any(r["status"] == "running" for r in runs.values())

    def ref() -> str:
        b = run(["git", "-C", str(root), "rev-parse", "--abbrev-ref", "HEAD"], check=False)
        s = run(["git", "-C", str(root), "rev-parse", "--short", "HEAD"], check=False)
        return f"{b.out.strip()}@{s.out.strip()}" if b.rc == 0 and s.rc == 0 else "local"

    def findings_by_root_path(stack) -> dict[str, list]:
        out: dict[str, list] = {}
        for c in _jload(out_root / stack.name / "checks.json") or []:
            for f in c["findings"]:
                out.setdefault(f"{stack.path}/{f['file']}", []).append({**f, "tool": c["name"], "rank": RANK.get(f["severity"], 1)})
        return out

    def resolve(d: dict):
        if d.get("app"):
            a = reg.apps.get(d["app"])
            return ("docker", a) if a else None
        st = reg.stacks.get(d.get("stack"))
        return ("tf", st) if st else None

    def matrix() -> list[dict]:
        m = [{"name": x.name, "kind": "tf", "env": x.env, "status": (runs.get(x.name) or {}).get("status", "idle")} for x in reg.stacks.values()]
        return m + [{"name": a.name, "kind": "docker", "env": "docker", "status": (runs.get(a.name) or {}).get("status", "idle")}
                    for a in reg.apps.values()]

    def checks_of(name: str) -> list:
        return _jload(out_root / name / "checks.json") or []

    def compute_fixes(kind, obj):
        res = checks_of(obj.name)
        if kind == "docker":
            return remediate.docker_fixes(obj, root, res)
        return remediate.tf_fixes(obj, root, res, check_run or run, tf_bin)

    def start_recheck(kind, obj):
        """Re-run only the static checks (fast) after a fix. Caller holds `lock`."""
        state["counter"] += 1
        if kind == "docker":
            r = dockerflow.new_run(state["counter"], obj, ref())
            runs[obj.name] = r
            rec = Recorder(r)
            fn = lambda: dockerflow.execute_docker_pipeline(r, rec, obj, root, out_root, check_run or run, which or shutil.which, only="lint")
        else:
            r = new_run(state["counter"], obj, ref())
            runs[obj.name] = r
            rec = Recorder(r)
            sp = specs_dir / f"{obj.name}.yaml"
            spec, _ = validate_spec(yaml.safe_load(sp.read_text()), reg)
            fn = lambda: execute_pipeline(r, rec, obj, spec, make_deployer, root, out_root, tf_bin, check_run or run, which or shutil.which, only="checks")

        def work():
            try:
                fn()
            except Exception as e:
                rec.fail(f"{type(e).__name__}: {e}")
        threading.Thread(target=work, daemon=True).start()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code: int, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else (body if isinstance(body, str) else json.dumps(body)).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data)

        def _guard(self, q) -> bool:
            p = self.server.server_address[1]
            if self.headers.get("Host") not in (f"127.0.0.1:{p}", f"localhost:{p}"):
                self._send(403, {"error": "bad host"}); return False
            if (q.get("t") or [self.headers.get("X-Token")])[0] != token:
                self._send(403, {"error": "bad token"}); return False
            return True

        def _stack(self, q):
            name = (q.get("stack") or [""])[0]
            return reg.stacks.get(name)

        def do_GET(self):
            u = urlparse(self.path); q = parse_qs(u.query)
            if not self._guard(q):
                return
            if u.path == "/":
                return self._send(200, PAGE, "text/html; charset=utf-8")
            d = {k: v[0] for k, v in q.items()}
            if u.path == "/api/stacks":
                return self._send(200, matrix())
            t = resolve(d)
            if t is None:
                return self._send(404, {"error": "unknown stack or app"})
            kind, st = t
            if u.path == "/api/run":
                info = ({"name": st.name, "env": "docker", "path": st.path, "region": "local", "account": "docker", "argocd_app": False, "kind": "docker"}
                        if kind == "docker" else
                        {"name": st.name, "env": st.env, "path": st.path, "region": st.region, "account": st.account_id,
                         "argocd_app": bool(st.argocd_app), "kind": "tf"})
                return self._send(200, {"stack": info, "run": snapshot(runs.get(st.name)),
                                        "skeleton": dockerflow.skeleton() if kind == "docker" else skeleton(st),
                                        "checks": checks_of(st.name), "matrix": matrix()})
            if u.path == "/api/tree":
                return self._send(200, build_tree(root, st.path, findings_by_root_path(st), _changed(root)))
            if u.path == "/api/file":
                rel = (q.get("path") or [""])[0]
                p = (root / rel).resolve()
                ok = p.is_file() and p.is_relative_to(root) and not any(
                    part in SKIP_DIRS or (part.startswith(".") and part not in KEEP_DOT) for part in p.relative_to(root).parts)
                if not ok or (p.suffix not in EXTS and p.name not in KEEP_DOT) or p.stat().st_size > MAX_FILE:
                    return self._send(400, {"error": "file not available"})
                ann = [{**f, "tool": f["tool"]} for f in findings_by_root_path(st).get(p.relative_to(root).as_posix(), [])]
                return self._send(200, {"path": rel, "content": p.read_text(errors="replace"), "ann": ann})
            if u.path == "/api/fixes":
                try:
                    fixes, manual = compute_fixes(kind, st)
                except Exception as e:
                    return self._send(200, {"fixes": [], "manual": [], "history": [], "error": f"{type(e).__name__}: {e}"})
                strip = [{**f, "files": [{"path": x["path"], "diff": x["diff"], "new": x["before"] is None} for x in f["files"]]} for f in fixes]
                return self._send(200, {"fixes": strip, "manual": manual[:60], "history": remediate.history(out_root / st.name / "fixes.json")})
            if u.path == "/api/explain":
                if kind != "docker":
                    return self._send(400, {"error": "docker apps only"})
                dpath = root / st.path / "Dockerfile"
                if not dpath.exists():
                    return self._send(404, {"error": "no Dockerfile"})
                text = dpath.read_text()
                img = _jload(out_root / st.name / "image.json") or {}
                import hashlib
                fresh = img.get("dockerfile_sha") == hashlib.sha256(dpath.read_bytes()).hexdigest()
                doc = dfile.explain(text, img.get("sizes") if fresh else None, dfile.lint(text, (root / st.path / ".dockerignore").exists()))
                doc["image"] = img.get("info") if fresh else None
                doc["built"] = fresh
                return self._send(200, doc)
            if u.path == "/api/topology":
                if kind != "docker":
                    return self._send(400, {"error": "docker apps only"})
                dpath = root / st.path / "Dockerfile"
                if not dpath.exists():
                    return self._send(404, {"error": "no Dockerfile"})
                return self._send(200, dfile.topology(dpath.read_text(), st))
            if u.path == "/api/gitops":
                if not st.argocd_app:
                    return self._send(200, {"configured": False})
                try:
                    return self._send(200, {"configured": True, **argo.detail(st.argocd_app)})
                except FileNotFoundError:
                    return self._send(200, {"configured": True, "error": "argocd CLI not installed"})
                except Exception as e:
                    return self._send(200, {"configured": True, "error": f"{type(e).__name__}: {str(e)[-300:]}"})
            self._send(404, {"error": "not found"})

        def do_POST(self):
            u = urlparse(self.path); q = parse_qs(u.query)
            if not self._guard(q):
                return
            try:
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
            except ValueError:
                return self._send(400, {"error": "bad json"})
            t = resolve(body)
            if t is None:
                return self._send(404, {"error": "unknown stack or app"})
            kind, st = t

            if u.path == "/api/fix" or u.path == "/api/fix/undo":
                with lock:
                    if busy():
                        return self._send(409, {"error": "a run is in progress"})
                    base = st.path
                    store = out_root / st.name / "fixes.json"
                    try:
                        if u.path == "/api/fix/undo":
                            res = remediate.undo_last(root, store)
                        else:
                            done, seen = [], set()
                            for _ in range(12):
                                fixes, _m = compute_fixes(kind, st)
                                pick = next((f for f in fixes if f["id"] not in seen and (body.get("all") or f["id"] == body.get("fix_id"))), None)
                                if pick is None:
                                    break
                                remediate.apply_fix(root, base, pick, store)
                                done.append(pick["title"])
                                seen.add(pick["id"])
                                if not body.get("all"):
                                    break
                            if not done:
                                return self._send(404, {"error": "fix not available (already applied or files changed)"})
                            res = {"applied": done}
                    except remediate.FixError as e:
                        return self._send(409, {"error": str(e)})
                    try:
                        start_recheck(kind, st)
                    except Exception as e:
                        return self._send(200, {**res, "recheck": f"not started: {type(e).__name__}: {e}"})
                return self._send(200, {**res, "recheck": "started"})

            if u.path == "/api/run" and kind == "docker":
                with lock:
                    if busy():
                        return self._send(409, {"error": "another run is in progress"})
                    state["counter"] += 1
                    r = dockerflow.new_run(state["counter"], st, ref())
                    runs[st.name] = r
                rec = Recorder(r)

                def work_d():
                    try:
                        dockerflow.execute_docker_pipeline(r, rec, st, root, out_root, check_run or run, which or shutil.which)
                    except Exception as e:
                        rec.fail(f"{type(e).__name__}: {e}")
                threading.Thread(target=work_d, daemon=True).start()
                return self._send(202, {"started": True, "id": r["id"]})

            if kind != "tf":
                return self._send(404, {"error": "not found"})

            if u.path == "/api/run":
                sp = specs_dir / f"{st.name}.yaml"
                if not sp.exists():
                    return self._send(400, {"error": f"spec file not found: {sp}"})
                try:
                    spec, _ = validate_spec(yaml.safe_load(sp.read_text()), reg)
                except Exception as e:
                    return self._send(400, {"error": f"{type(e).__name__}: {e}"})
                with lock:
                    if busy():
                        return self._send(409, {"error": "another run is in progress"})
                    state["counter"] += 1
                    r = new_run(state["counter"], st, ref())
                    runs[st.name] = r
                rec = Recorder(r)

                def work():
                    try:
                        execute_pipeline(r, rec, st, spec, make_deployer, root, out_root, tf_bin,
                                         check_run or run, which or shutil.which)
                    except Exception as e:
                        rec.fail(f"{type(e).__name__}: {e}")
                threading.Thread(target=work, daemon=True).start()
                return self._send(202, {"started": True, "id": r["id"]})

            if u.path == "/api/apply":
                r = runs.get(st.name)
                meta = _jload(out_root / st.name / "meta.json")
                with lock:
                    if not r or r["status"] != "waiting" or not meta:
                        return self._send(409, {"error": "no plan is waiting for approval"})
                    if body.get("confirm") != meta["plan_sha"][:8]:
                        return self._send(400, {"error": "confirm must equal the first 8 chars of the plan hash"})
                    r["status"] = "running"
                rec = Recorder(r)

                def work():
                    try:
                        execute_apply(r, rec, st, make_deployer, argo)
                    except Exception as e:
                        rec.fail(f"{type(e).__name__}: {e}")
                threading.Thread(target=work, daemon=True).start()
                return self._send(202, {"started": True})
            self._send(404, {"error": "not found"})

    return ThreadingHTTPServer(("127.0.0.1", port), H)


PAGE = r"""<!doctype html><meta charset=utf-8><title>deploy-agent</title>
<style>
:root{--bg:#0d1117;--sub:#161b22;--bd:#30363d;--tx:#e6edf3;--mu:#8b949e;--gr:#3fb950;--rd:#f85149;--ye:#d29922;--bl:#58a6ff;--hv:#1f2630;--code:#0b0f14}
@media(prefers-color-scheme:light){:root{--bg:#fff;--sub:#f6f8fa;--bd:#d0d7de;--tx:#1f2328;--mu:#656d76;--gr:#1a7f37;--rd:#cf222e;--ye:#9a6700;--bl:#0969da;--hv:#eaeef2;--code:#f6f8fa}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:14px/1.5 -apple-system,"Segoe UI",system-ui,sans-serif}
button{font:inherit;color:var(--tx);background:var(--sub);border:1px solid var(--bd);border-radius:6px;padding:5px 14px;cursor:pointer}button:hover{background:var(--hv)}
button.go{background:#238636;border-color:#2ea043;color:#fff;font-weight:600}button:disabled{opacity:.5;cursor:default}
input{font:inherit;color:var(--tx);background:var(--bg);border:1px solid var(--bd);border-radius:6px;padding:5px 10px}
.top{display:flex;align-items:center;gap:10px;padding:12px 24px;background:var(--sub);border-bottom:1px solid var(--bd)}.top b{font-size:15px}.mu{color:var(--mu)}
.wrap{max-width:1500px;margin:0 auto;padding:20px 24px}h1{margin:0;font-size:22px;font-weight:600}
.matrix{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0}.pill{display:flex;gap:8px;align-items:center;border-radius:999px;padding:4px 14px}.pill.on{border-color:var(--bl);box-shadow:0 0 0 1px var(--bl)}
.graph{display:flex;align-items:center;gap:0;overflow-x:auto;padding:14px;border:1px solid var(--bd);border-radius:8px;background:var(--sub)}
.jobbox{display:flex;gap:10px;align-items:center;min-width:190px;padding:10px 14px;border:1px solid var(--bd);border-radius:8px;background:var(--bg);cursor:pointer}.jobbox.sel{border-color:var(--bl);box-shadow:0 0 0 1px var(--bl)}
.arrow{width:34px;height:2px;background:var(--bd);flex:none}
.ic{display:inline-flex;width:18px;height:18px;border-radius:50%;align-items:center;justify-content:center;font-size:11px;font-weight:700;flex:none;border:2px solid var(--mu);color:var(--mu)}
.ic.success{background:var(--gr);border-color:var(--gr);color:#fff}.ic.failure{background:var(--rd);border-color:var(--rd);color:#fff}
.ic.warning,.ic.waiting{background:var(--ye);border-color:var(--ye);color:#fff}.ic.skipped{border-style:dashed}.ic.running{border-color:var(--ye) var(--ye) var(--ye) transparent;animation:s 1s linear infinite}
@keyframes s{to{transform:rotate(360deg)}}
.cols{display:grid;grid-template-columns:300px minmax(0,1fr);gap:16px;margin-top:16px;align-items:start}
.box{border:1px solid var(--bd);border-radius:8px;overflow:hidden}.boxh{padding:8px 12px;background:var(--sub);border-bottom:1px solid var(--bd);font-weight:600}
#tree{padding:6px 4px;font-size:13px;max-height:72vh;overflow:auto}.tn{display:flex;gap:6px;align-items:center;padding:2px 6px;border-radius:6px;cursor:pointer;white-space:nowrap}.tn:hover{background:var(--hv)}.tn.cur{background:var(--hv);font-weight:600}
.bdg{margin-left:auto;border-radius:999px;padding:0 7px;font-size:11px;color:#fff;background:var(--ye)}.bdg.h{background:var(--rd)}.dot{width:7px;height:7px;border-radius:50%;background:var(--bl)}
.tabs{display:flex;gap:4px;border-bottom:1px solid var(--bd);margin-bottom:12px}.tabs button{border:0;border-bottom:2px solid transparent;border-radius:0;background:none}.tabs button.on{border-color:#f78166;font-weight:600}
details{border:1px solid var(--bd);border-radius:8px;margin-bottom:8px;overflow:hidden}summary{display:flex;gap:10px;align-items:center;padding:8px 12px;cursor:pointer;background:var(--sub)}.sn{flex:1}
pre.log{margin:0;max-height:68vh;min-height:90px;overflow:auto;background:var(--code);padding:6px 0;font:12px/1.55 ui-monospace,Menlo,Consolas,monospace}
.ln{display:flex}.ln .n{flex:none;width:44px;text-align:right;padding-right:12px;color:var(--mu);user-select:none}.ln .t{white-space:pre-wrap;word-break:break-word;flex:1;padding-right:12px}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px}.chip{border:1px solid var(--bd);border-radius:999px;padding:2px 12px;font-size:12px}
.chip.pass{border-color:var(--gr);color:var(--gr)}.chip.fail,.chip.error{border-color:var(--rd);color:var(--rd)}.chip.warn{border-color:var(--ye);color:var(--ye)}
.ann{border:1px solid var(--bd);border-left:4px solid var(--ye);border-radius:6px;padding:6px 10px;margin-bottom:6px;cursor:pointer}.ann:hover{background:var(--hv)}.ann.high,.ann.critical,.ann.error{border-left-color:var(--rd)}
.sev{font-size:11px;border-radius:4px;padding:0 6px;background:var(--ye);color:#fff}.sev.high,.sev.critical,.sev.error{background:var(--rd)}
.appr{border:1px solid var(--ye);border-radius:8px;padding:14px;margin-bottom:12px;background:var(--sub)}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.vb{border-radius:999px;padding:1px 10px;font-weight:600;font-size:12px;color:#fff}.vb.auto,.vb.noop{background:var(--gr)}.vb.needs_approval{background:var(--ye)}.vb.deny{background:var(--rd)}
table.code{border-collapse:collapse;width:100%;font:12px/1.55 ui-monospace,Menlo,Consolas,monospace;background:var(--code)}table.code td{padding:0 10px;vertical-align:top}td.n{width:1%;color:var(--mu);text-align:right;user-select:none}td.c{white-space:pre-wrap;word-break:break-word}
tr.hl td{background:rgba(210,153,34,.18)}tr.annr td{background:var(--sub);font-family:inherit;color:var(--ye)}
table.res{width:100%;border-collapse:collapse}table.res td,table.res th{text-align:left;padding:4px 8px;border-bottom:1px solid var(--bd)}
.fixbox{border:1px solid var(--gr);border-radius:8px;padding:12px;margin-bottom:14px;background:var(--sub)}.fix{border:1px solid var(--bd);border-radius:8px;padding:10px 12px;margin-top:10px;background:var(--bg)}
.why{color:var(--mu);margin:4px 0 6px}.diff{font:12px/1.5 ui-monospace,Menlo,Consolas,monospace;border:1px solid var(--bd);border-radius:6px;overflow:auto;max-height:260px;background:var(--code)}
.diff div{padding:0 10px;white-space:pre}.diff .add{background:rgba(63,185,80,.18)}.diff .del{background:rgba(248,81,73,.18)}.diff .hk{color:var(--bl)}.diff .hd{color:var(--mu)}
.img h2{font-size:16px;margin:18px 0 6px}.cards{display:flex;gap:10px;flex-wrap:wrap;margin:10px 0}.card{border:1px solid var(--bd);border-radius:8px;padding:8px 14px;background:var(--sub);min-width:120px}.card b{display:block;font-size:18px}
.stages{display:flex;gap:14px;align-items:flex-start;flex-wrap:wrap}.stage{flex:1;min-width:340px;border:1px solid var(--bd);border-radius:10px;overflow:hidden}.stage.gone{border-style:dashed;opacity:.85}.stage .boxh{display:flex;gap:8px;align-items:center}
.tag{font-size:11px;border-radius:999px;padding:0 8px;border:1px solid var(--bd);color:var(--mu)}.tag.ship{border-color:var(--gr);color:var(--gr)}
.st{display:flex;gap:10px;padding:8px 12px;border-top:1px solid var(--bd)}.kw{flex:none;width:92px;font:600 11px ui-monospace,Menlo,monospace;color:var(--bl);padding-top:3px}
.st .pl{font-size:14px}.st code{display:block;color:var(--mu);font-size:11px;word-break:break-all;margin-top:2px}.sz{height:6px;background:var(--bl);border-radius:3px;margin-top:5px}
.layer{border-left:4px solid var(--bl)}.meta{border-left:4px solid var(--bd)}.glos{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:8px}.glos div{border:1px solid var(--bd);border-radius:8px;padding:8px 12px;background:var(--sub)}
.shell{display:flex;min-height:100vh}.main{flex:1;min-width:0}
.side{width:208px;flex:none;position:sticky;top:0;height:100vh;background:var(--sub);border-right:1px solid var(--bd);padding:14px 10px;display:flex;flex-direction:column;gap:2px}
.side a{display:flex;gap:10px;align-items:center;padding:7px 10px;border-radius:6px;color:var(--mu);font-size:14px;cursor:pointer}
.side a:hover{background:var(--hv);color:var(--tx)}.side a.on{background:var(--hv);color:var(--tx);font-weight:600}
.side a.off{opacity:.45;cursor:default}.side a.off:hover{background:none;color:var(--mu)}
.side a i{font-style:normal;width:18px;text-align:center}.side .soon{margin-left:auto;font-size:10px;border:1px solid var(--bd);border-radius:999px;padding:0 6px}
.envs{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px;margin:14px 0}
.env{border:1px solid var(--bd);border-radius:10px;padding:12px 14px;background:var(--sub);cursor:pointer}.env:hover{background:var(--hv)}.env.on{border-color:var(--bl);box-shadow:0 0 0 1px var(--bl)}
.env .hd{display:flex;gap:8px;align-items:center;font-weight:600}.env .ban{margin-top:10px;padding:6px 10px;border-radius:6px;font-size:13px}
.ban.success{background:rgba(63,185,80,.15);color:var(--gr)}.ban.failure{background:rgba(248,81,73,.15);color:var(--rd)}
.ban.waiting,.ban.running,.ban.warning{background:rgba(210,153,34,.15);color:var(--ye)}.ban.idle{background:var(--hv);color:var(--mu)}
.cols.wide{grid-template-columns:420px minmax(0,1fr)}
.wbs{width:100%;height:auto;color:var(--mu)}.wbs text{fill:var(--tx);font:13px -apple-system,"Segoe UI",system-ui,sans-serif}
.wbs .m{fill:var(--mu);font-size:11.5px}.wbs .mono{font-family:ui-monospace,Menlo,monospace;font-size:11px}.wbs .b{font-weight:600}
.wbs .g{fill:var(--gr)}.wbs .y{fill:var(--ye)}.wbs .r{fill:var(--rd)}
.wbs .card{fill:var(--bg);stroke:var(--bd)}.wbs .bpill{fill:rgba(63,185,80,.15);stroke:var(--gr)}.wbs .host{fill:none;stroke:var(--bd);stroke-dasharray:6 4}
.wbs .net{fill:rgba(63,185,80,.08);stroke:var(--gr)}.wbs .ctr{fill:var(--sub);stroke:var(--bl)}.wbs .vol{fill:var(--bg);stroke:var(--mu);stroke-dasharray:5 4}
.wbs line{stroke:var(--mu);stroke-width:1.5}
@media(max-width:900px){.cols{grid-template-columns:1fr}.cols.wide{grid-template-columns:1fr}.side{display:none}}
</style>
<div class=shell><nav class=side id=side aria-label="Sections"></nav><div class=main>
<div class=top><b>deploy-agent</b><span class=mu id=repo></span><span style=flex:1></span><button class=go id=runbtn>Run pipeline</button></div>
<div class=wrap>
<h1 id=title>Pipeline</h1><div id=sub class=mu style="margin-top:4px"></div>
<div class=envs id=matrix></div>
<div class=graph id=graph></div>
<div class=cols>
 <aside><div class=box id=wbbox style="display:none;margin-bottom:12px"><div class=boxh>How it runs</div><div id=wb style="padding:10px"></div></div><div class=box><div class=boxh>Files</div><div id=tree class=mu>loading</div></div></aside>
 <section>
  <div class=tabs><button data-tab=logs class=on>Logs</button><button data-tab=code>Code</button><button data-tab=argo id=argotab style="display:none">ArgoCD</button><button data-tab=image id=imgtab style="display:none">Image</button></div>
  <div id=appr></div><div id=jobview></div><div id=codeview style="display:none"></div><div id=argoview style="display:none"></div><div id=imgview class=img style="display:none"></div>
 </section>
</div></div>
</div></div>
<script>
const T=new URLSearchParams(location.search).get('t');const $=id=>document.getElementById(id);
const S={tpKey:'',kind:'tf',fixes:null,fixKey:'',fixErr:'',explain:null,exKey:'',stack:null,stacks:[],data:null,sel:'checks',tab:'logs',open:{},fold:{},tree:null,file:null,last:'',treeKey:'',apprKey:'',cur:null};
const RANK={critical:4,high:3,error:3,medium:2,warning:2,low:1,notice:1,info:0};
const api=(p,o={})=>fetch(p+(p.includes('?')?'&':'?')+'t='+T,{...o,headers:{'X-Token':T,'Content-Type':'application/json'}}).then(r=>r.json().then(j=>({ok:r.ok,j})));
const esc=s=>String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const dur=(a,b)=>{if(!a)return '';const s=Math.max(0,Math.round((b||Date.now()/1000)-a));return s<60?s+'s':Math.floor(s/60)+'m '+(s%60)+'s'};
const IC={success:'✓',failure:'✕',waiting:'!',warning:'!',skipped:''};
const ic=s=>`<span class="ic ${s}">${IC[s]||''}</span>`;
const enc=encodeURIComponent;

const qs=()=>(S.kind==='docker'?'app=':'stack=')+enc(S.stack);
async function boot(){const r=await api('/api/stacks');S.stacks=r.j;S.stack=S.stacks[0].name;S.kind=S.stacks[0].kind;S.sel=S.kind==='docker'?'lint':'checks';await poll();loop()}
function loop(){setTimeout(async()=>{await poll();if(S.tab==='argo')loadArgo();if(S.tab==='image')loadExplain();if(S.kind==='docker')loadTopology();loop()},(S.data&&S.data.run&&S.data.run.status==='running')?800:2500)}
async function poll(){const r=await api('/api/run?'+qs());if(!r.ok)return;const txt=JSON.stringify(r.j);
 if(txt!==S.last){S.last=txt;S.data=r.j;render()}
 const run=r.j.run;const k=S.stack+':'+(run?run.id+run.status:'idle');if(k!==S.treeKey){S.treeKey=k;loadTree()}
 const fk=k+':'+(run&&run.status==='running'?'r':'i')+JSON.stringify(r.j.checks).length;if(!(run&&run.status==='running')&&fk!==S.fixKey){S.fixKey=fk;loadFixes()}}
async function loadFixes(){const r=await api('/api/fixes?'+qs());if(r.ok){S.fixes=r.j;S.last='';poll()}}

function render(){const d=S.data,run=d.run,st=d.stack,jobs=(run||{jobs:d.skeleton}).jobs;
 $('repo').textContent='/ '+st.path;$('title').textContent=(st.kind==='docker'?'Image ':run?'Deploy ':'Pipeline ')+st.name;$('imgtab').style.display=st.kind==='docker'?'':'none';
 $('sub').innerHTML=run?`${ic(run.status)} <b>${esc(run.status)}</b> · run #${run.id} · ${st.kind==='docker'?'local docker':esc(st.account)+' · '+esc(st.region)} · ${esc(run.ref||'local')} · ${dur(run.started,run.ended)}`:'No run yet for this stack. Click Run pipeline.';
 $('runbtn').disabled=!!(run&&run.status==='running');
 $('matrix').innerHTML=d.matrix.map(envCard).join('');
 $('graph').innerHTML=jobs.map((j,i)=>{const sub=j.status==='waiting'?'waiting for approval':j.status==='skipped'?'skipped':j.status==='pending'?'queued':dur(j.started,j.ended);
  return `<div class="jobbox ${S.sel===j.name?'sel':''}" data-j="${j.name}">${ic(j.status==='pending'?'pending':j.status)}<div><b>${esc(j.title)}</b><div class=mu style="font-size:12px">${esc(sub)}</div></div></div>${i<jobs.length-1?'<span class=arrow></span>':''}`}).join('');
 $('argotab').style.display=st.argocd_app?'':'none';
 const ak=run?run.id+run.status:'';if(ak!==S.apprKey){S.apprKey=ak;renderAppr(run)}
 renderJob(jobs.find(j=>j.name===S.sel)||jobs[0],d);setTabs();renderSide();
 document.querySelector('.cols').classList.toggle('wide',st.kind==='docker');if(st.kind==='docker')loadTopology();else $('wbbox').style.display='none'}

function renderAppr(run){const el=$('appr');if(!run||run.status!=='waiting'){el.innerHTML='';return}
 const c=run.counts||{};const p=(run.plan_sha||'').slice(0,8);
 el.innerHTML=`<div class=appr><div class=row>${ic('waiting')}<b>Review required: apply to ${esc(run.env)}</b><span class="vb ${esc(run.verdict)}">${esc((run.verdict||'').toUpperCase())}</span><span class=mu>+${c.create||0} ~${c.update||0} -${c.delete||0} replace ${c.replace||0}</span></div>
 <div class=mu style="margin:8px 0">Type the first 8 characters of the plan hash to approve exactly this plan: <code>${esc(p)}</code></div>
 <div class=row><input id=confirm size=12 placeholder="${esc(p)}" autocomplete=off><button class=go id=applybtn>Approve and apply</button><span id=apperr style="color:var(--rd)"></span></div></div>`}

function stepHTML(j,s){const k=j.name+'.'+s.name;const o=S.open[k]!==undefined?S.open[k]:(s.status==='running'||s.status==='failure');
 const body=s.log?s.log.split(/\r?\n/).map((l,i)=>`<div class=ln><span class=n>${i+1}</span><span class=t>${esc(l)}</span></div>`).join(''):`<div class=mu style="padding:8px 14px">${s.status==='pending'?'Waiting to run':s.status==='skipped'?'Skipped':'No output'}</div>`;
 return `<details data-k="${k}" ${o?'open':''}><summary>${ic(s.status==='pending'?'pending':s.status)}<span class=sn>${esc(s.title)}</span><span class=mu>${dur(s.started,s.ended)}</span></summary><pre class=log data-k="${k}">${body}</pre></details>`}

function checksHTML(d){const cs=d.checks||[];if(!cs.length)return '';
 const chips=cs.map(c=>`<span class="chip ${c.status}">${esc(c.name)} · ${esc(c.summary)}</span>`).join('');
 const all=cs.flatMap(c=>c.findings.map(f=>({...f,tool:c.name}))).sort((a,b)=>(RANK[b.severity]||0)-(RANK[a.severity]||0)).slice(0,40);
 return `<div class=chips>${chips}</div>`+(all.length?`<div style="margin-bottom:12px"><div class=mu style="margin-bottom:6px">Annotations (click to open the file)</div>${all.map(f=>`<div class="ann ${esc(f.severity)}" ${f.file==='image'?'':'data-open="'+esc(f.file)+'"'} data-line="${f.line}"><span class="sev ${esc(f.severity)}">${esc(f.severity)}</span> <b>${esc(f.tool)}</b> ${esc(f.rule)} <span class=mu>${esc(f.file)}:${f.line}</span><div>${esc(f.msg)}</div></div>`).join('')}</div>`:'')}

function renderJob(j,d){const sc={};document.querySelectorAll('#jobview pre[data-k]').forEach(p=>sc[p.dataset.k]=[p.scrollTop,p.scrollHeight-p.clientHeight-p.scrollTop<10]);
 $('jobview').innerHTML=`<div class=row style="margin-bottom:10px">${ic(j.status==='pending'?'pending':j.status)}<b style="font-size:16px">${esc(j.title)}</b><span class=mu>${dur(j.started,j.ended)}</span></div>`+(j.name==='checks'||j.name==='lint'?fixesHTML()+checksHTML(d):'')+j.steps.map(s=>stepHTML(j,s)).join('');
 document.querySelectorAll('#jobview pre[data-k]').forEach(p=>{const v=sc[p.dataset.k];  if(v&&!v[1])p.scrollTop=v[0];else p.scrollTop=p.scrollHeight})}

function setTabs(){document.querySelectorAll('.tabs button').forEach(b=>b.classList.toggle('on',b.dataset.tab===S.tab));
 $('jobview').style.display=$('appr').style.display=S.tab==='logs'?'':'none';$('codeview').style.display=S.tab==='code'?'':'none';$('argoview').style.display=S.tab==='argo'?'':'none';$('imgview').style.display=S.tab==='image'?'':'none'}

async function loadTree(){const r=await api('/api/tree?'+qs());if(!r.ok)return;S.tree=r.j;renderTree()}
const isOpen=(n,depth)=>S.fold[n.path]!==undefined?S.fold[n.path]:(depth<=3||S.tree.stack===n.path||S.tree.stack.startsWith(n.path+'/'));
function renderTree(){const t=S.tree;const row=(n,depth)=>{const pad=`style="padding-left:${6+depth*14}px"`;
  if(n.type==='dir'){const o=isOpen(n,depth);return `<div class=tn ${pad} data-p="${esc(n.path)}" data-d=1><span class=mu>${o?'▾':'▸'}</span><span>${esc(n.name)}</span></div>`+(o?n.children.map(c=>row(c,depth+1)).join(''):'')}
  const b=n.findings?`<span class="bdg ${n.worst>=3?'h':''}">${n.findings}</span>`:'';
  return `<div class="tn ${S.file===n.path?'cur':''}" ${pad} data-p="${esc(n.path)}"><span class=mu>·</span><span>${esc(n.name)}</span>${n.changed?'<span class=dot title="changed in git"></span>':''}${b}</div>`};
 $('tree').innerHTML=t.root.children.map(c=>row(c,0)).join('')||'<div class=mu style="padding:8px">no files found under --root</div>'}

async function openPath(p,line){S.tab='code';S.file=p;setTabs();renderTree();
 const r=await api('/api/file?'+qs()+'&path='+enc(p));if(!r.ok){$('codeview').innerHTML='<div class=mu>'+esc(r.j.error)+'</div>';return}
 const ann={};r.j.ann.forEach(a=>(ann[a.line]=ann[a.line]||[]).push(a));
 const rows=r.j.content.split(/\r?\n/).map((l,i)=>{const n=i+1,a=ann[n];return `<tr id="L${n}" class="${a?'hl':''}"><td class=n>${n}</td><td class=c>${esc(l)}</td></tr>`+(a?a.map(x=>`<tr class=annr><td></td><td><span class="sev ${esc(x.severity)}">${esc(x.severity)}</span> ${esc(x.tool)} ${esc(x.rule)}: ${esc(x.msg)}</td></tr>`).join(''):'')}).join('');
 $('codeview').innerHTML=`<div class=box><div class=boxh>${esc(p)}</div><table class=code>${rows}</table></div>`;
 if(line){const e=$('L'+line);if(e)e.scrollIntoView({block:'center'})}}

const gcls=v=>['Synced','Healthy'].includes(v)?'success':['Degraded','Missing'].includes(v)?'failure':['OutOfSync','Progressing','Suspended'].includes(v)?'warning':'skipped';
async function loadArgo(){const r=await api('/api/gitops?stack='+enc(S.stack));if(!r.ok)return;const g=r.j;const el=$('argoview');
 if(!g.configured){el.innerHTML='<div class=mu>No ArgoCD app configured for this stack. Set argocd_app in config/stacks.yaml.</div>';return}
 if(g.error){el.innerHTML=`<div style="color:var(--rd)">${esc(g.error)}</div><div class=mu>Start the dashboard with ARGOCD_OPTS="--core" (kubeconfig) or ARGOCD_SERVER and ARGOCD_AUTH_TOKEN.</div>`;return}
 el.innerHTML=`<div class=row><b>${esc(g.app)}</b>${ic(gcls(g.sync))}<span>${esc(g.sync)}</span>${ic(gcls(g.health))}<span>${esc(g.health)}</span><code>${esc((g.revision||'').slice(0,8))}</code></div>
 <div class=mu style="margin:4px 0 10px">${esc(g.repo||'')} · ${esc(g.path||'')} @ ${esc(g.target||'')} → ${esc(g.cluster||'')}/${esc(g.namespace||'')}</div>
 <table class=res><tr><th>kind</th><th>name</th><th>sync</th><th>health</th><th></th></tr>${g.resources.map(x=>`<tr><td>${esc(x.kind)}</td><td>${esc(x.name)}</td><td>${ic(gcls(x.sync))} ${esc(x.sync)}</td><td>${ic(gcls(x.health))} ${esc(x.health)}</td><td class=mu>${esc(x.message)}</td></tr>`).join('')||'<tr><td class=mu colspan=5>no resources</td></tr>'}</table>
 <div class=mu style="margin-top:8px">${g.history.map(h=>'#'+esc(h.id)+' '+esc((h.revision||'').slice(0,8))).join(' · ')}</div>`}

const tgt=()=>S.kind==='docker'?{app:S.stack}:{stack:S.stack};
async function doFix(body,url='/api/fix'){S.fixErr='';const r=await api(url,{method:'POST',body:JSON.stringify(body)});if(!r.ok)S.fixErr=r.j.error;S.sel=S.kind==='docker'?'lint':'checks';S.tab='logs';S.last='';S.fixKey='';S.fixes=null;poll()}
function diffHTML(d){return '<div class=diff>'+String(d).split('\n').filter((l,i,a)=>!(i===a.length-1&&l==='')).map(l=>`<div class="${l.startsWith('+++')||l.startsWith('---')?'hd':l[0]==='+'?'add':l[0]==='-'?'del':l.startsWith('@@')?'hk':''}">${esc(l)||' '}</div>`).join('')+'</div>'}
function fixesHTML(){const f=S.fixes;let o='';if(S.fixErr)o+=`<div class=ann style="border-left-color:var(--rd)">${esc(S.fixErr)}</div>`;if(!f)return o;const fx=f.fixes||[],mn=f.manual||[],h=f.history||[];if(!fx.length&&!mn.length&&!h.length)return o;
 o+=`<div class=fixbox><div class=row><b style="font-size:15px">Remediation</b><span class=mu>${fx.length} automatic fix${fx.length==1?'':'es'}${mn.length?' · '+mn.length+' need a manual change':''}</span><span style=flex:1></span>${h.length?'<button id=fixundo title="'+esc(h[h.length-1].title)+'">Undo last fix</button>':''}${fx.length>1?`<button class=go id=fixall>Apply all ${fx.length} fixes</button>`:''}</div>`;
 o+=fx.map(x=>`<div class=fix><div class=row><b>${esc(x.title)}</b><span style=flex:1></span><button class=go data-fix="${esc(x.id)}">Apply fix</button></div><div class=why>${esc(x.why)}</div><div class=chips>${x.resolves.map(r=>`<span class=chip>clears ${esc(r)}</span>`).join('')}</div>${x.files.map(fl=>`<div class=mu style="margin:6px 0 2px">${esc(fl.path)}${fl.new?' (new file)':''}</div>${diffHTML(fl.diff)}`).join('')}</div>`).join('');
 if(!fx.length)o+=`<div class=mu style="margin-top:8px">${mn.length?'No automatic fix is left. Re-run the pipeline to continue.':'Everything that could be fixed automatically has been fixed.'}</div>`;
 if(mn.length)o+=`<details style="margin-top:10px"><summary><span class=sn>${mn.length} finding(s) with no safe automatic fix (shown as annotations below)</span></summary><div style="padding:8px 12px" class=mu>${mn.map(m=>esc(m.check)+' '+esc(m.rule)+' '+esc(m.file)+':'+m.line+' '+esc(m.msg)).join('<br>')}</div></details>`;
 return o+'</div>'}
const BAN={success:'All checks passed',failure:'Failed: open the failing job below',waiting:'Waiting for approval',running:'Running',idle:'No run yet'};
function envCard(m){const s=BAN[m.status]?m.status:'idle',sel=m.name===S.stack;
 const n=sel&&S.data&&S.data.checks?S.data.checks.reduce((a,c)=>a+c.findings.length,0):0;
 return `<div class="env ${sel?'on':''}" data-s="${esc(m.name)}" data-kind="${esc(m.kind)}" role=button tabindex=0><div class=hd>${ic(s==='idle'?'pending':s)}<span>${esc(m.name)}</span><span class=tag>${esc(m.env)}</span><span class=tag>${m.kind==='docker'?'docker':'terraform'}</span></div><div class="ban ${s}">${BAN[s]}${n?' · '+n+' finding'+(n==1?'':'s'):''}</div></div>`}
const NAV=[['▦','Dashboard'],['▢','Containers'],['≣','Logs','logs'],['>','Shell'],['≋','Stacks','stacks'],['▣','Images','images'],['▭','Volumes'],['⌘','Networks'],['⇣','Registry'],['∿','Activity'],['◷','Schedules'],['⚙','Settings']];
function renderSide(){const cur=S.kind==='docker'?'images':'stacks';
 $('side').innerHTML=NAV.map(([i,n,k])=>k?`<a data-nav="${k}" class="${k===cur?'on':''}"><i>${i}</i>${n}</a>`:`<a class=off title="Not built yet" aria-disabled=true><i>${i}</i>${n}<span class=soon>soon</span></a>`).join('')}
function go(n){if(n==='logs'){S.tab='logs';setTabs();return}
 const dk=n==='images';const m=(S.data?S.data.matrix:S.stacks).find(x=>(x.kind==='docker')===dk);if(!m)return;
 S.stack=m.name;S.kind=m.kind||'tf';S.sel=dk?'lint':'checks';S.fixes=null;S.fixKey='';S.exKey='';S.last='';S.treeKey='';S.file=null;S.tab=dk?'image':'logs';poll();if(dk)loadExplain()}
async function loadTopology(){const s=S.stack;const r=await api('/api/topology?'+qs());if(s!==S.stack)return;const b=$('wbbox');
 if(!r.ok){b.style.display='none';return}b.style.display='';const k=JSON.stringify(r.j);if(k===S.tpKey)return;S.tpKey=k;$('wb').innerHTML=wbSVG(r.j)}
function wbSVG(t){const Y=n=>n+14,cut=(s,n)=>{s=String(s);return s.length>n?s.slice(0,n-1)+'…':s},p=t.ports[0];
 const vols=t.volumes.length?t.volumes.slice(0,3).map((v,i)=>`<text class="m mono" x="312" y="${Y(282+i*18)}" text-anchor="middle">${esc(cut(v,14))}</text>`).join('')+(t.volumes.length>3?`<text class=m x="312" y="${Y(336)}" text-anchor="middle">+${t.volumes.length-3} more</text>`:''):`<text class=m x="312" y="${Y(282)}" text-anchor="middle">none</text><text class=m x="312" y="${Y(300)}" text-anchor="middle">stateless</text><text class=m x="312" y="${Y(318)}" text-anchor="middle">logs → stdout</text>`;
 const label=`Runtime topology of ${t.name}: Dockerfile builds an image that runs on the ${t.network} network, host port ${p.host} maps to container port ${p.container}, ${t.volumes.length?t.volumes.length+' volume(s)':'no volumes'}`;
 return `<svg class=wbs viewBox="0 0 400 ${Y(546)}" role=img aria-label="${esc(label)}"><defs><marker id=wbm viewBox="0 0 10 10" refX=8 refY=5 markerWidth=6 markerHeight=6 orient=auto-start-reverse><path d="M2 1L8 5L2 9" fill=none stroke=currentColor stroke-width=1.5 stroke-linecap=round stroke-linejoin=round /></marker></defs>
 <rect class=card x=90 y=10 width=220 height=100 rx=8 /><text class=b x=200 y=30 text-anchor=middle>Dockerfile</text>
 <text class="m mono" x=104 y=50>FROM ${esc(cut(t.base,24))}${t.stages>1?' ('+t.stages+' stages)':''}</text>
 <text class="mono ${p.exposed?'m':'y'}" x=104 y=66>${p.exposed?'EXPOSE '+p.container:'no EXPOSE '+p.container}</text>
 <text class="mono ${t.root?'r':'m'}" x=104 y=82>USER ${esc(cut(t.user,18))}</text>
 <text class="mono ${t.healthcheck?'m':'y'}" x=104 y=98>${t.healthcheck?'HEALTHCHECK '+esc(cut(t.health_path,10)):'no HEALTHCHECK'}</text>
 <line x1=200 y1=111 x2=200 y2=${Y(106)} marker-end="url(#wbm)" /><rect class=bpill x=110 y=${Y(108)} width=180 height=28 rx=6 /><text class=g x=200 y=${Y(126)} text-anchor=middle>docker build, docker run</text>
 <line x1=200 y1=${Y(137)} x2=200 y2=${Y(156)} marker-end="url(#wbm)" />
 <rect class=host x=12 y=${Y(158)} width=376 height=262 rx=14 /><text class=b x=26 y=${Y(178)}>Docker host (your machine)</text>
 <rect class=net x=26 y=${Y(190)} width=348 height=150 rx=10 /><text class="g b" x=40 y=${Y(210)}>${esc(t.network==='bridge'?'Bridge network (default)':t.network)}</text>
 <rect class=ctr x=44 y=${Y(222)} width=200 height=102 rx=8 /><text class=b x=144 y=${Y(244)} text-anchor=middle>${esc(cut(t.name,22))}</text>
 <text class=m x=144 y=${Y(264)} text-anchor=middle>${esc(cut(t.base,26))}</text>
 <text class="m ${t.shell_form?'y':''}" x=144 y=${Y(282)} text-anchor=middle>PID 1: ${esc(cut(t.shell_form?'sh -c '+t.cmd:t.cmd,t.shell_form?15:20))}</text>
 <text class="m ${t.root?'r':''}" x=144 y=${Y(300)} text-anchor=middle>user ${esc(cut(t.user,18))}</text>
 <rect class=vol x=262 y=${Y(222)} width=100 height=102 rx=8 /><text class=b x=312 y=${Y(248)} text-anchor=middle>Volumes</text>${vols}
 <line x1=144 y1=${Y(325)} x2=144 y2=${Y(456)} marker-end="url(#wbm)" />
 <text class=b x=158 y=${Y(378)}>Port mapping</text><text class="${p.exposed?'m':'y'}" x=158 y=${Y(394)}>Host:${p.host} → Container:${p.container}</text>
 ${p.exposed?'':`<text class="y" x=158 y=${Y(410)}>EXPOSE does not list ${p.container}</text>`}${t.extra_ports.length?`<text class=m x=158 y=${Y(p.exposed?410:426)}>also EXPOSEd: ${esc(t.extra_ports.join(', '))}</text>`:''}
 <rect class=card x=84 y=${Y(460)} width=120 height=44 rx=8 /><text x=144 y=${Y(487)} text-anchor=middle>Your browser</text>
 <line x1=205 y1=${Y(482)} x2=232 y2=${Y(482)} marker-end="url(#wbm)" /><rect class=card x=234 y=${Y(466)} width=154 height=32 rx=6 /><text class=mono x=311 y=${Y(486)} text-anchor=middle>localhost:${p.host}</text></svg>`}
async function loadExplain(){const r=await api('/api/explain?'+qs());if(!r.ok){$('imgview').innerHTML='<div class=mu>'+esc(r.j.error)+'</div>';return}const k=JSON.stringify(r.j);if(k===S.exKey)return;S.exKey=k;const e=r.j;
 const mx=Math.max(1,...e.stages.flatMap(s=>s.steps.map(x=>x.size||0)));const mb=n=>n>=1e6?(n/1e6).toFixed(1)+' MB':n>=1e3?Math.round(n/1e3)+' KB':n+' B';
 const im=e.image;
 const cards=im?`<div class=cards><div class=card><span class=mu>Final size</span><b>${im.size_mb} MB</b></div><div class=card><span class=mu>Layers</span><b>${im.layer_count}</b></div><div class=card><span class=mu>Runs as</span><b>${esc(im.user)}</b></div><div class=card><span class=mu>Healthcheck</span><b>${im.healthcheck?'yes':'none'}</b></div><div class=card><span class=mu>Platform</span><b>${esc(im.os_arch)}</b></div></div>`:`<div class=mu style="margin:8px 0">Not built yet. Sizes appear after a successful run.</div>`;
 $('imgview').innerHTML=`<h2 style="margin-top:0">How this image is built, in plain words</h2><div>A Dockerfile is a recipe. Docker follows it top to bottom and each <b>RUN</b>, <b>COPY</b> or <b>ADD</b> step adds one read-only <b>layer</b>, like a transparent sheet stacked on the previous ones. The result is the <b>image</b>: a sealed, repeatable package of your app. ${e.multistage?'This recipe has <b>two stages</b>: the first builds, the second ships. Only the second becomes the image.':'This recipe has a single stage, so everything used to build also ships.'}</div>${cards}
 <div class=stages>${e.stages.map(s=>`<div class="stage ${s.discarded?'gone':''}"><div class=boxh><span>Stage: ${esc(s.name)}</span><span class="tag ${s.final?'ship':''}">${s.final?'shipped as the image':'thrown away after the build'}</span></div>${s.steps.map(x=>`<div class="st ${x.layer?'layer':'meta'}"><div class=kw>${esc(x.kw)}</div><div style="flex:1"><div class=pl>${esc(x.plain)}</div><code>${esc(x.text)}</code>${x.issues.map(i=>`<div class=ann style="margin-top:6px;cursor:default;padding:2px 8px"><span class="sev ${esc(i.severity)}">${esc(i.rule)}</span> ${esc(i.msg)}</div>`).join('')}${x.size!=null&&x.layer?`<div class=sz style="width:${Math.max(2,Math.round(100*x.size/mx))}%"></div><span class=mu style="font-size:11px">adds ${mb(x.size)}</span>`:''}</div><span class=tag>${x.layer?'layer':'setting'}</span></div>`).join('')}</div>`).join('')}</div>
 <h2>Words you will see</h2><div class=glos>${e.glossary.map(g=>`<div><b>${esc(g.term)}</b><div class=mu>${esc(g.text)}</div></div>`).join('')}</div>`}

document.addEventListener('toggle',e=>{const k=e.target.dataset&&e.target.dataset.k;if(k&&e.target.tagName==='DETAILS')S.open[k]=e.target.open},true);
document.addEventListener('keydown',e=>{if(e.key==='Enter'&&e.target.classList&&e.target.classList.contains('env'))e.target.click()});
document.addEventListener('click',async e=>{const t=e.target;let el;
 if(el=t.closest('[data-nav]')){go(el.dataset.nav);return}
 if(el=t.closest('[data-s]')){S.stack=el.dataset.s;S.kind=el.dataset.kind||'tf';S.sel=S.kind==='docker'?'lint':'checks';S.fixes=null;S.fixKey='';S.exKey='';S.last='';S.treeKey='';S.file=null;S.tab='logs';poll();return}
 if(el=t.closest('[data-j]')){S.sel=el.dataset.j;S.tab='logs';render();return}
 if(el=t.closest('[data-tab]')){S.tab=el.dataset.tab;setTabs();if(S.tab==='argo')loadArgo();if(S.tab==='image'){S.exKey='';loadExplain()}return}
 if(el=t.closest('#tree [data-p]')){if(el.dataset.d){S.fold[el.dataset.p]=!isOpen({path:el.dataset.p},0);renderTree()}else openPath(el.dataset.p);return}
 if(el=t.closest('[data-open]')){openPath(S.data.stack.path+'/'+el.dataset.open,+el.dataset.line);return}
 if(t.id==='runbtn'){const r=await api('/api/run',{method:'POST',body:JSON.stringify(tgt())});if(!r.ok)$('sub').textContent='Could not start: '+r.j.error;S.sel=S.kind==='docker'?'lint':'checks';S.tab='logs';S.last='';poll();return}
 if(el=t.closest('[data-fix]')){await doFix({...tgt(),fix_id:el.dataset.fix});return}
 if(t.id==='fixall'){await doFix({...tgt(),all:true});return}
 if(t.id==='fixundo'){await doFix(tgt(),'/api/fix/undo');return}
 if(t.id==='applybtn'){const r=await api('/api/apply',{method:'POST',body:JSON.stringify({stack:S.stack,confirm:$('confirm').value.trim()})});if(!r.ok){$('apperr').textContent=r.j.error;return}S.sel='apply';S.last='';poll()}});
boot();
</script>"""
