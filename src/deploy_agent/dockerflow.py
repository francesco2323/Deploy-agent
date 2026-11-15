"""Docker pipeline: lint -> build -> scan -> test -> ready. Local only: nothing is pushed anywhere.

lint  : captain (built-in best practices), hadolint, trivy config
build : docker daemon, build, rebuild (cache stability), inspect (layers/size/user)
scan  : trivy image vulnerabilities, SBOM (CycloneDX)
test  : hardened run (read-only fs, no caps, limits), healthcheck, HTTP smoke, non-root, graceful stop
Same Recorder/run model as the Terraform pipeline, so the dashboard renders both identically.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import dockerfile as df
from .checks import CheckResult, RANK, _human, _trivy
from .pipeline import LOCK, STEP_STATUS, Recorder
from .runner import run
from .spec import App

CHECKS = ("captain", "hadolint", "trivy")
HELP = {"hadolint": "brew install hadolint", "trivy": "brew install trivy", "vulns": "brew install trivy"}
DEFAULT_MODE = {"captain": "block", "hadolint": "block", "trivy": "block", "vulns": "warn"}


def skeleton() -> list[dict]:
    spec = [
        ("lint", "Lint", [("captain", "Docker best practices"), ("hadolint", "hadolint"), ("trivy", "trivy config")]),
        ("build", "Build", [("daemon", "Docker daemon"), ("build", "docker build"), ("rebuild", "Rebuild (cache is stable)"), ("inspect", "Inspect image layers")]),
        ("scan", "Scan", [("vulns", "trivy image: vulnerabilities"), ("sbom", "SBOM (CycloneDX)")]),
        ("test", "Test", [("run", "Start hardened container"), ("health", "Healthcheck turns healthy"), ("http", "HTTP smoke test"),
                          ("user", "Runs as non-root"), ("stop", "Graceful stop (SIGTERM)")]),
        ("ready", "Ready", [("summary", "Image ready")]),
    ]
    return [{"name": n, "title": t, "status": "pending", "started": None, "ended": None,
             "steps": [{"name": sn, "title": st, "status": "pending", "started": None, "ended": None, "log": ""} for sn, st in steps]}
            for n, t, steps in spec]


def new_run(rid: int, app: App, ref: str) -> dict:
    return {"id": rid, "stack": app.name, "env": "docker", "kind": "docker", "status": "running", "started": time.time(),
            "ended": None, "ref": ref, "verdict": None, "plan_sha": None, "counts": None, "error": None, "jobs": skeleton()}


def mode_for(app: App, name: str) -> str:
    return app.checks.get(name) or DEFAULT_MODE[name]


def source_hash(adir: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(adir.rglob("*")):
        if p.is_file() and not any(x in p.parts for x in (".git", "__pycache__", ".venv", "node_modules")):
            h.update(p.relative_to(adir).as_posix().encode())
            h.update(p.read_bytes())
    return h.hexdigest()[:12]


def _grade(fs: list[dict]) -> str:
    if not fs:
        return "pass"
    return "fail" if max(RANK.get(f["severity"], 1) for f in fs) >= 2 else "warn"


def _finish(res: CheckResult, mode: str) -> CheckResult:
    if res.status == "fail" and mode == "warn":
        res.status = "warn"
    return res


# ------------------------------------------------------------------ lint
def run_lint(app: App, adir: Path, run_fn=run, which=shutil.which) -> list[CheckResult]:
    out = []
    for name in CHECKS:
        mode = mode_for(app, name)
        t0 = time.time()
        if mode == "off":
            out.append(CheckResult(name, "skipped", "disabled for this app", log=f"{name}: mode=off"))
            continue
        try:
            if name == "captain":
                fs = df.lint((adir / "Dockerfile").read_text(), (adir / ".dockerignore").exists())
                r = CheckResult(name, _grade(fs), f"{len(fs)} issue(s)" if fs else "all best-practice checks pass", fs,
                                _human(fs) or "captain: Dockerfile follows the best practices we check", round(time.time() - t0, 2))
            elif not which(name):
                r = CheckResult(name, "skipped", f"{name} not installed", log=f"{name} not found. Install: {HELP[name]}")
            elif name == "hadolint":
                x = run_fn(["hadolint", "--format", "json", "Dockerfile"], cwd=adir, check=False)
                if x.rc not in (0, 1):
                    r = CheckResult(name, "error", "hadolint failed", log=(x.err or x.out)[-3000:])
                else:
                    sev = {"error": "high", "warning": "medium", "info": "low", "style": "low"}
                    fs = [{"file": "Dockerfile", "line": int(i.get("line") or 1), "severity": sev.get(str(i.get("level")), "low"),
                           "rule": i.get("code", ""), "msg": i.get("message", "")} for i in json.loads(x.out or "[]")]
                    r = CheckResult(name, _grade(fs), f"{len(fs)} issue(s)" if fs else "no issues", fs, _human(fs) or "hadolint: clean")
            else:
                status, summary, fs, log = _trivy(adir, "", run_fn)
                if status == "error":
                    r = CheckResult(name, "error", summary, log=log)
                else:
                    r = CheckResult(name, _grade(fs), summary, fs, log)
                    for f in r.findings:
                        f["file"] = f["file"] or "Dockerfile"
        except Exception as e:  # tool crash is an error, never a pass
            r = CheckResult(name, "error", type(e).__name__, log=str(e)[-2000:])
        r.duration = round(time.time() - t0, 2)
        out.append(_finish(r, mode))
    return out


def http_probe(url: str, timeout: float = 3.0) -> tuple[int, str]:
    if not url.startswith("http://127.0.0.1:"):
        raise ValueError("probe is local-only")
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:  # noqa: S310 (local only, checked above)
            return r.status, r.read(300).decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:  # connection refused etc.
        return 0, str(e)


# ------------------------------------------------------------------ pipeline
def execute_docker_pipeline(run_: dict, rec: Recorder, app: App, root: Path, out_root: Path, run_fn=run, which=shutil.which,
                            probe=None, sleep=time.sleep, only: str | None = None) -> None:
    probe = probe or http_probe  # resolved at call time so tests can swap it
    adir = Path(root) / app.path
    out = Path(out_root) / app.name
    out.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []

    def save():
        (out / "checks.json").write_text(json.dumps(results))

    def sh(argv, timeout=1800, env=None):
        r = run_fn(argv, cwd=adir, check=False, timeout=timeout, env=env)
        rec.log(f"$ {' '.join(argv)}\n{(r.out + r.err).strip()}\n")
        return r

    # ---- lint
    if not (adir / "Dockerfile").exists():
        rec.start("captain")
        return rec.fail(f"No Dockerfile in {app.path}")
    blocked = False
    for res in run_lint(app, adir, run_fn, which):
        rec.start(res.name)
        results.append(res.to_dict())
        rec.log(f"{res.log}\n\n{res.summary}")
        rec.finish(STEP_STATUS[res.status])
        blocked |= res.status in ("fail", "error")
    save()
    rec.end_job("lint", "failure" if blocked else "success")
    if blocked:
        return rec.fail("Lint failed. Open the Fixes panel to apply the proposed remediations, then re-run.")
    if only == "lint":
        rec._skip_pending()
        with LOCK:
            run_.update(status="success", ended=time.time())
        return

    tag, latest = f"{app.image}:{source_hash(adir)}", f"{app.image}:local"
    cname = f"deploy-agent-{app.name}-{int(time.time())}"
    try:
        # ---- build
        rec.start("daemon")
        if not which("docker"):
            return rec.fail("docker is not installed. Install Docker Desktop.")
        r = sh(["docker", "info", "--format", "{{.ServerVersion}}"])
        if r.rc != 0:
            return rec.fail("Docker daemon not reachable. Start Docker Desktop and run again.")
        rec.finish("success")
        build = ["docker", "build", "--progress=plain", "-t", tag, "-t", latest,
                 "--label", f"org.opencontainers.image.revision={run_.get('ref', 'local')}", "."]
        rec.start("build")
        r = sh(build, env={"DOCKER_BUILDKIT": "1"})
        if r.rc != 0:
            return rec.fail("docker build failed (see log).")
        rec.finish("success")
        rec.start("rebuild")
        r2 = sh(build, env={"DOCKER_BUILDKIT": "1"})
        txt = r2.out + r2.err
        steps = len(re.findall(r"^#\d+ \[(?:\S+ )?\d+/\d+\] (?:RUN|COPY|ADD)", txt, re.M))
        cached = len(re.findall(r"^#\d+ CACHED", txt, re.M))
        if r2.rc != 0:
            return rec.fail("rebuild failed.")
        if steps and cached < steps:
            rec.finish("warning", f"{steps - cached} of {steps} layers were rebuilt on an unchanged tree: something in the Dockerfile is not deterministic.")
        else:
            rec.finish("success", f"Second build reused all {steps} layers from cache: the build is deterministic and fast.")
        rec.start("inspect")
        info = inspect_image(adir, tag, sh)
        if info is None:
            return rec.fail("could not inspect the built image.")
        rec.log(json.dumps({k: v for k, v in info["info"].items() if k != "layers"}, indent=2))
        (out / "image.json").write_text(json.dumps({"dockerfile_sha": hashlib.sha256((adir / "Dockerfile").read_bytes()).hexdigest(),
                                                    "tag": tag, **info}))
        rec.finish("success")
        rec.end_job("build", "success")

        # ---- scan
        rec.start("vulns")
        mode = mode_for(app, "vulns")
        if mode == "off" or not which("trivy"):
            rec.finish("skipped", "disabled" if mode == "off" else f"trivy not installed. Install: {HELP['vulns']}")
            results.append(CheckResult("vulns", "skipped", "trivy not installed" if mode != "off" else "disabled").to_dict())
        else:
            x = sh(["trivy", "image", "--format", "json", "--quiet", "--severity", "HIGH,CRITICAL", "--ignore-unfixed", tag], 900)
            if x.rc != 0:
                results.append(CheckResult("vulns", "error", "trivy image failed", log=x.err[-2000:]).to_dict())
                return rec.fail("trivy image scan failed.")
            fs = []
            for res in json.loads(x.out or "{}").get("Results") or []:
                for v in res.get("Vulnerabilities") or []:
                    fs.append({"file": "image", "line": 1, "severity": str(v.get("Severity", "high")).lower(), "rule": v.get("VulnerabilityID", ""),
                               "msg": f"{v.get('PkgName')} {v.get('InstalledVersion')} -> fixed in {v.get('FixedVersion')}: {v.get('Title', '')}"[:200]})
            cr = _finish(CheckResult("vulns", "fail" if fs else "pass", f"{len(fs)} fixable HIGH/CRITICAL vulnerabilities" if fs else "no fixable HIGH/CRITICAL vulnerabilities", fs[:100]), mode)
            results.append(cr.to_dict())
            rec.log(f"{len(fs)} fixable HIGH/CRITICAL vulnerabilities. Fix: bump the base image tag or the library version.")
            rec.finish(STEP_STATUS[cr.status])
            if cr.status == "fail":
                save()
                rec.end_job("scan", "failure")
                return rec.fail("Fixable HIGH/CRITICAL vulnerabilities found.")
        save()
        rec.start("sbom")
        if not which("trivy"):
            rec.finish("skipped", "trivy not installed")
        else:
            sbom = out / "sbom.cdx.json"
            x = sh(["trivy", "image", "--format", "cyclonedx", "--output", str(sbom), "--quiet", tag], 900)
            n = len((json.loads(sbom.read_text()).get("components") or [])) if x.rc == 0 and sbom.exists() else 0
            rec.finish("success" if x.rc == 0 else "warning", f"SBOM written: {sbom} ({n} components)" if x.rc == 0 else "SBOM generation failed")
        rec.end_job("scan", "success")

        # ---- test
        rec.start("run")
        r = sh(["docker", "run", "-d", "--name", cname, "--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges:true", "--pids-limit", "128", "--memory", "256m", "--cpus", "1",
                "-p", f"127.0.0.1::{app.port}", tag])
        if r.rc != 0:
            return rec.fail("container failed to start.")
        pr = sh(["docker", "port", cname, f"{app.port}/tcp"])
        m = re.search(r":(\d+)\s*$", (pr.out or "").strip().splitlines()[0] if pr.out.strip() else "")
        if pr.rc != 0 or not m:
            return rec.fail(f"app did not publish port {app.port}. Does the Dockerfile EXPOSE the right port?")
        hp = int(m.group(1))
        rec.finish("success", f"running as {cname} on 127.0.0.1:{hp} (read-only filesystem, all capabilities dropped, 256 MB, 128 pids)")
        rec.start("health")
        status, waited = "starting", 0
        while waited < 90:
            hs = sh(["docker", "inspect", "-f", "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.State.Running}}", cname])
            status, _, running = (hs.out.strip() or "?|?").partition("|")
            if status == "healthy" or status == "none" or running == "false" or status == "unhealthy":
                break
            sleep(2)
            waited += 2
        if status != "healthy":
            sh(["docker", "logs", "--tail", "40", cname])
            return rec.fail({"none": "no HEALTHCHECK defined in the image.", "unhealthy": "HEALTHCHECK reports unhealthy."}.get(status, f"container not healthy (state: {status})."))
        rec.finish("success")
        rec.start("http")
        code, body = 0, ""
        for _ in range(5):
            code, body = probe(f"http://127.0.0.1:{hp}{app.health_path}")
            if code:
                break
            sleep(1)
        rec.log(f"GET {app.health_path} -> {code} {body[:120]}")
        if code != 200:
            return rec.fail(f"GET {app.health_path} returned {code}, expected 200.")
        rec.finish("success")
        rec.start("user")
        u = sh(["docker", "inspect", "-f", "{{.Config.User}}", cname]).out.strip()
        uid = sh(["docker", "exec", cname, "id", "-u"]).out.strip().splitlines()[-1:] or ["?"]
        if u in ("", "root", "0") or uid[0] == "0":
            return rec.fail(f"container runs as root (configured user: {u or 'none'}, uid {uid[0]}).")
        rec.finish("success", f"configured user '{u}', effective uid {uid[0]}")
        rec.start("stop")
        t0 = time.time()
        sh(["docker", "stop", "-t", "10", cname])
        dt = time.time() - t0
        ec = sh(["docker", "inspect", "-f", "{{.State.ExitCode}}", cname]).out.strip()
        logs = sh(["docker", "logs", "--tail", "100", cname])
        rec.log(f"stopped in {dt:.1f}s with exit code {ec}")
        if ec not in ("0", "143") or dt >= 9:
            return rec.fail(f"app ignored SIGTERM (exit code {ec}, {dt:.1f}s): it was killed. Handle SIGTERM or use exec-form CMD.")
        rec.finish("warning" if "Traceback" in logs.out + logs.err else "success",
                   "Python traceback found in container logs." if "Traceback" in logs.out + logs.err else "")
        rec.end_job("test", "success")

        # ---- ready
        rec.start("summary")
        size = info["info"]["size_mb"]
        rec.log(f"image   {tag}\nalso    {latest}\nsize    {size} MB, {info['info']['layer_count']} layers\nuser    {info['info']['user']}\n"
                f"run it  docker run --rm -p {app.port}:{app.port} {latest}\n(nothing was pushed: local run only)")
        rec.finish("success")
        rec.end_job("ready", "success")
        with LOCK:
            run_.update(status="success", ended=time.time())
    finally:
        run_fn(["docker", "rm", "-f", cname], cwd=adir, check=False)
        save()


def inspect_image(adir: Path, tag: str, sh) -> dict | None:
    r = sh(["docker", "image", "inspect", tag])
    if r.rc != 0:
        return None
    d = json.loads(r.out)[0]
    cfg = d.get("Config") or {}
    h = sh(["docker", "history", "--no-trunc", "--human=false", "--format", "{{json .}}", tag])
    hist = [json.loads(l) for l in h.out.splitlines() if l.strip().startswith("{")] if h.rc == 0 else []
    info = {"id": d.get("Id", "")[:19], "size_mb": round(d.get("Size", 0) / 1e6, 1), "layer_count": len((d.get("RootFS") or {}).get("Layers") or []),
            "user": cfg.get("User") or "root (default)", "healthcheck": bool(cfg.get("Healthcheck")),
            "ports": sorted((cfg.get("ExposedPorts") or {}).keys()), "cmd": cfg.get("Cmd"), "entrypoint": cfg.get("Entrypoint"),
            "os_arch": f"{d.get('Os')}/{d.get('Architecture')}", "digests": d.get("RepoDigests") or []}
    return {"info": info, "sizes": align_sizes((adir / "Dockerfile").read_text(), hist)}


def align_sizes(text: str, hist: list[dict]) -> list | None:
    """Pair the FINAL stage's instructions with docker history (newest first). None if the pairing looks wrong."""
    sts = df.stages(df.parse(text))
    if not sts or not hist:
        return None
    ins = sts[-1]["ins"]
    top = hist[: len(ins)]
    if len(top) < len(ins):
        return None
    top = list(reversed(top))
    ok = sum(1 for x, h in zip(ins, top) if x["kw"].lower() in str(h.get("CreatedBy", "")).lower())
    if ok < max(1, int(0.8 * len(ins))):
        return None
    out = []
    for h in top:
        try:
            out.append(int(float(str(h.get("Size", 0)).strip() or 0)))
        except ValueError:
            out.append(0)
    return out
