import shutil

import pytest
import threading
import time
from pathlib import Path

from deploy_agent import dockerflow
from deploy_agent.spec import App, Registry
from deploy_agent.ui import make_server
from fakedocker import FakeDocker
from test_ui import TOKEN, call

SAMPLE = Path(__file__).resolve().parent / "fixtures" / "sample-app"


def serve(tmp_path, monkeypatch=None):
    root = tmp_path / "root"
    shutil.copytree(SAMPLE, root / "apps/a")
    reg = Registry({}, (), {"a": App("a", "apps/a", "deploy-agent/a")})
    fake = FakeDocker()
    srv = make_server(reg, root, tmp_path / "out", tmp_path / "specs", None, TOKEN, check_run=fake,
                      which=lambda t: "/bin/docker" if t == "docker" else None)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1], root, fake


def wait(port, pred):
    for _ in range(300):
        d = call(port, "/api/run?app=a")[1]
        if d["run"] and pred(d["run"]):
            return d
        time.sleep(0.05)
    raise AssertionError(d["run"] and d["run"]["status"])


def test_matrix_lists_apps_and_docker_run_requires_fixes_first(tmp_path):
    srv, port, root, fake = serve(tmp_path)
    try:
        m = call(port, "/api/stacks")[1]
        assert m == [{"name": "a", "kind": "docker", "env": "docker", "status": "idle"}]
        assert call(port, "/api/run", "POST", {"app": "a"})[0] == 202
        d = wait(port, lambda r: r["status"] != "running")
        assert d["run"]["status"] == "failure" and d["stack"]["kind"] == "docker"
        assert [c["name"] for c in d["checks"]] == ["captain", "hadolint", "trivy"]
        assert {f["rule"] for f in d["checks"][0]["findings"]} >= {"CAP001", "CAP002", "CAP003"}
        assert call(port, "/api/run", "POST", {"app": "nope"})[0] == 404
    finally:
        srv.shutdown()


def test_fixes_endpoint_hides_file_contents_and_apply_all_then_pipeline_passes(tmp_path, monkeypatch):
    monkeypatch.setattr(dockerflow, "http_probe", lambda u, timeout=3.0: (200, "ok"))
    srv, port, root, fake = serve(tmp_path)
    try:
        call(port, "/api/run", "POST", {"app": "a"})
        wait(port, lambda r: r["status"] != "running")
        f = call(port, "/api/fixes?app=a")[1]
        ids = [x["id"] for x in f["fixes"]]
        assert "docker-pin-base" in ids and "docker-dockerignore" in ids
        assert all(set(fl) == {"path", "diff", "new"} for x in f["fixes"] for fl in x["files"]), "no raw before/after to client"
        orig = (root / "apps/a/Dockerfile").read_text()
        st, j = call(port, "/api/fix", "POST", {"app": "a", "all": True})
        assert st == 200 and j["recheck"] == "started" and len(j["applied"]) >= 8
        d = wait(port, lambda r: r["status"] in ("success", "failure") and r["id"] == 2)
        assert d["run"]["status"] == "success" and all(c["status"] == "pass" for c in d["checks"] if c["name"] == "captain")
        assert call(port, "/api/fixes?app=a")[1]["fixes"] == []
        assert call(port, "/api/run", "POST", {"app": "a"})[0] == 202
        d = wait(port, lambda r: r["id"] == 3 and r["status"] != "running")
        assert d["run"]["status"] == "success" and [j["status"] for j in d["run"]["jobs"]] == ["success"] * 5
        ex = call(port, "/api/explain?app=a")[1]
        assert ex["multistage"] and ex["built"] and ex["image"]["size_mb"] == 61.0
        # undo walks the history back, one fix at a time, to the original file
        for _ in range(len(j["applied"])):
            assert call(port, "/api/fix/undo", "POST", {"app": "a"})[0] == 200
            wait(port, lambda r: r["status"] != "running")
        assert (root / "apps/a/Dockerfile").read_text() == orig and not (root / "apps/a/.dockerignore").exists()
        assert call(port, "/api/fix/undo", "POST", {"app": "a"})[0] == 409
    finally:
        srv.shutdown()


def test_single_fix_and_stale_or_unknown_fix_rejected(tmp_path):
    srv, port, root, fake = serve(tmp_path)
    try:
        call(port, "/api/run", "POST", {"app": "a"})
        wait(port, lambda r: r["status"] != "running")
        assert call(port, "/api/fix", "POST", {"app": "a", "fix_id": "../../etc/passwd"})[0] == 404
        assert call(port, "/api/fix", "POST", {"app": "a", "fix_id": "docker-pin-base"})[0] == 200
        wait(port, lambda r: r["id"] == 2 and r["status"] != "running")
        assert "FROM python:3.12-slim" in (root / "apps/a/Dockerfile").read_text()
        assert call(port, "/api/fix", "POST", {"app": "a", "fix_id": "docker-pin-base"})[0] == 404
    finally:
        srv.shutdown()


def test_tree_and_file_serve_dockerfile_but_not_hidden_or_outside(tmp_path):
    srv, port, root, fake = serve(tmp_path)
    try:
        (root / "apps/a/.env").write_text("SECRET=1")
        names = []
        def walk(n):
            names.append(n["name"]); [walk(c) for c in n.get("children", [])]
        walk(call(port, "/api/tree?app=a")[1]["root"])
        assert "Dockerfile" in names and "server.py" in names and ".env" not in names
        assert call(port, "/api/file?app=a&path=apps/a/Dockerfile")[0] == 200
        assert call(port, "/api/file?app=a&path=apps/a/.env")[0] == 400
        assert call(port, "/api/file?app=a&path=../x")[0] == 400
    finally:
        srv.shutdown()


def test_topology_endpoint_reflects_the_dockerfile_and_is_docker_only(tmp_path):
    srv, port, root, fake = serve(tmp_path)
    try:
        code, t = call(port, "/api/topology?app=a")
        assert code == 200 and t["root"] and t["volumes"] == [] and t["ports"][0]["container"] == 8080
        (root / "apps/a/Dockerfile").write_text('FROM python:3.12-slim\nVOLUME /data\nEXPOSE 8080\nUSER 10001:10001\nCMD ["python", "server.py"]\n')
        t = call(port, "/api/topology?app=a")[1]
        assert t["volumes"] == ["/data"] and not t["root"] and t["ports"][0]["exposed"] is True
        assert call(port, "/api/topology?app=nope")[0] in (400, 404)
        (root / "apps/a/Dockerfile").unlink()
        assert call(port, "/api/topology?app=a")[0] == 404
    finally:
        srv.shutdown()


def test_dashboard_shows_the_version_and_leaves_no_placeholder():
    from deploy_agent import __version__
    from deploy_agent.ui import PAGE
    html = PAGE.replace("@@VERSION@@", __version__)
    assert "deploy-agent v@@VERSION@@" in PAGE and f"deploy-agent v{__version__}" in html
    assert "@@VERSION@@" not in html
