import shutil
from pathlib import Path

import pytest

from deploy_agent import dockerflow as DF
from deploy_agent import remediate as R
from deploy_agent.pipeline import Recorder
from deploy_agent.spec import App
from fakedocker import FakeDocker

SAMPLE = Path(__file__).resolve().parents[2] / "infra-test" / "apps" / "sample-app"


@pytest.fixture
def env(tmp_path):
    app = App("a", "apps/a", "deploy-agent/a")
    root = tmp_path / "root"
    shutil.copytree(SAMPLE, root / "apps/a")
    return app, root, tmp_path / "out"


def fix_all(app, root):
    for _ in range(12):
        fx, _m = R.docker_fixes(app, root, [])
        if not fx:
            return
        R.apply_fix(root, app.path, fx[0], root / "fx.json")


def go(app, root, out, fake, **kw):
    r = DF.new_run(1, app, "local")
    rec = Recorder(r)
    DF.execute_docker_pipeline(r, rec, app, root, out, fake, kw.pop("which", lambda t: "/bin/" + t if t == "docker" else None),
                               probe=kw.pop("probe", lambda u: (200, '{"status": "ok"}')), sleep=lambda s: None, **kw)
    return r


def step(r, job, name):
    return next(s for j in r["jobs"] if j["name"] == job for s in j["steps"] if s["name"] == name)


def test_imperfect_dockerfile_blocks_before_anything_is_built(env):
    app, root, out = env
    fake = FakeDocker()
    r = go(app, root, out, fake)
    assert r["status"] == "failure" and "Fixes panel" in r["error"]
    assert step(r, "lint", "captain")["status"] == "failure"
    assert fake.calls == [] and all(s["status"] == "skipped" for j in r["jobs"][1:] for s in j["steps"])


def test_after_remediation_whole_pipeline_passes_and_cleans_up(env):
    app, root, out = env
    fix_all(app, root)
    fake = FakeDocker()
    r = go(app, root, out, fake)
    assert r["status"] == "success", r["error"]
    assert [j["status"] for j in r["jobs"]] == ["success"] * 5
    assert step(r, "build", "rebuild")["status"] == "success" and "all 2 layers" in step(r, "build", "rebuild")["log"]
    run_cmd = fake.subs("run")[0]
    for flag in ("--read-only", "--cap-drop", "no-new-privileges:true", "--pids-limit", "--memory"):
        assert flag in run_cmd
    assert "127.0.0.1::8080" in run_cmd, "port must bind loopback only"
    assert fake.subs("rm")[-1][-2:] == ["-f", run_cmd[run_cmd.index("--name") + 1]]
    assert not any(c[1] == "push" for c in fake.calls if c[0] == "docker"), "local run only"
    import json
    img = json.loads((out / "a" / "image.json").read_text())
    assert img["info"]["size_mb"] == 61.0 and img["sizes"] is None or isinstance(img["sizes"], list)


@pytest.mark.parametrize("opts,job,stepname,msg", [
    ({"daemon": False}, "build", "daemon", "Docker daemon not reachable"),
    ({"build_rc": 1}, "build", "build", "docker build failed"),
    ({"health": "unhealthy"}, "test", "health", "unhealthy"),
    ({"health": "none"}, "test", "health", "no HEALTHCHECK"),
    ({"uid": "0"}, "test", "user", "runs as root"),
    ({"exit": "137"}, "test", "stop", "ignored SIGTERM"),
    ({"port": ""}, "test", "run", "did not publish"),
])
def test_each_failure_is_reported_and_container_removed(env, opts, job, stepname, msg):
    app, root, out = env
    fix_all(app, root)
    fake = FakeDocker(**opts)
    r = go(app, root, out, fake)
    assert r["status"] == "failure" and msg in r["error"], r["error"]
    assert step(r, job, stepname)["status"] == "failure"
    assert fake.subs("rm"), "cleanup must always run"


def test_http_failure_fails(env):
    app, root, out = env
    fix_all(app, root)
    r = go(app, root, out, FakeDocker(), probe=lambda u: (500, ""))
    assert r["status"] == "failure" and "returned 500" in r["error"]


def test_uncached_rebuild_is_a_warning_not_a_failure(env):
    app, root, out = env
    fix_all(app, root)
    r = go(app, root, out, FakeDocker(rebuild_cached=False))
    assert r["status"] == "success" and step(r, "build", "rebuild")["status"] == "warning"


def test_vulns_warn_by_default_block_when_configured(env):
    app, root, out = env
    fix_all(app, root)
    v = [{"VulnerabilityID": "CVE-1", "Severity": "HIGH", "PkgName": "openssl", "InstalledVersion": "1", "FixedVersion": "2", "Title": "t"}]
    w = lambda t: "/bin/" + t
    r = go(app, root, out, FakeDocker(vulns=v), which=w)
    assert r["status"] == "success" and step(r, "scan", "vulns")["status"] == "warning"
    assert (out / "a" / "sbom.cdx.json").exists() and "3 components" in step(r, "scan", "sbom")["log"]
    blocked = App("a", "apps/a", "deploy-agent/a", checks={"vulns": "block"})
    r = go(blocked, root, out, FakeDocker(vulns=v), which=w)
    assert r["status"] == "failure" and r["jobs"][2]["status"] == "failure" and "vulnerabilities" in r["error"]


def test_hadolint_json_is_parsed_and_blocks(env):
    app, root, out = env
    fix_all(app, root)
    h = [{"code": "DL3059", "level": "warning", "line": 3, "message": "Multiple consecutive RUN"}]
    r = go(app, root, out, FakeDocker(hadolint=h), which=lambda t: "/bin/" + t)
    assert r["status"] == "failure" and step(r, "lint", "hadolint")["status"] == "failure"


def test_lint_only_mode_stops_after_lint(env):
    app, root, out = env
    fix_all(app, root)
    fake = FakeDocker()
    r = go(app, root, out, fake, only="lint")
    assert r["status"] == "success" and fake.calls == []


def test_missing_docker_is_a_clear_failure(env):
    app, root, out = env
    fix_all(app, root)
    r = go(app, root, out, FakeDocker(), which=lambda t: None)
    assert r["status"] == "failure" and "not installed" in r["error"]


def test_align_sizes_rejects_mismatched_history():
    t = "FROM python:3.12-slim\nWORKDIR /app\nCOPY . .\nCMD [\"x\"]\n"
    ok = [{"CreatedBy": "CMD [x]", "Size": "0"}, {"CreatedBy": "COPY . . # buildkit", "Size": "10"}, {"CreatedBy": "WORKDIR /app", "Size": "0"}]
    assert DF.align_sizes(t, ok) == [0, 10, 0]
    assert DF.align_sizes(t, [{"CreatedBy": "weird", "Size": "1"}] * 3) is None
    assert DF.align_sizes(t, ok[:1]) is None


def test_cli_docker_lint_only_exit_codes(env, capsys):
    from deploy_agent.cli import main
    app, root, out = env
    cfg = root / "stacks.yaml"
    cfg.write_text("stacks: {}\napps:\n  a: {path: apps/a}\n")
    args = ["--registry", str(cfg), "--root", str(root), "--out", str(out), "docker", "--app", "a", "--lint-only"]
    assert main(args) == 3 and "Lint failed" in capsys.readouterr().out
    fix_all(app, root)
    assert main(args) == 0 and "docker pipeline OK" in capsys.readouterr().out
