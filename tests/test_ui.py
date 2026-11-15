import dataclasses
import json
import threading
import time
import urllib.error
import urllib.request

import yaml

from conftest import plan_of, rc
from deploy_agent.audit import Audit
from deploy_agent.runner import Result
from deploy_agent.spec import Registry
from deploy_agent.ui import make_server
from deploy_agent.workflow import Deployer

TOKEN = "tok"


def call(port, path, method="GET", body=None, token=TOKEN, host=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"X-Token": token, "Content-Type": "application/json"})
    if host:
        req.add_header("Host", host)
    try:
        with urllib.request.urlopen(req) as r:
            raw = r.read()
            return r.status, json.loads(raw) if "json" in r.headers.get("Content-Type", "") else raw
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def wait_for(port, pred, stack="s"):
    for _ in range(200):
        d = call(port, f"/api/run?stack={stack}")[1]
        if d["run"] and pred(d["run"]):
            return d
        time.sleep(0.05)
    raise AssertionError(f"timeout: {d['run'] and d['run']['status']}")


def serve(harness, plan, env="dev", reg_edit=None, check_run=None, which=None, argo=None):
    d, reg, log, tmp = harness(plan, env=env)
    if reg_edit:
        reg = Registry({"s": dataclasses.replace(reg.stacks["s"], **reg_edit)})
    specs = tmp / "specs"; specs.mkdir()
    (specs / "s.yaml").write_text(yaml.safe_dump({"stack": "s"}))
    sd = tmp / "root" / reg.stacks["s"].path
    (sd / "main.tf").write_text('resource "aws_s3_bucket" "t" {\n  bucket = "b1"\n}\n')
    (sd / ".terraform").mkdir(); (sd / ".terraform" / "junk.tf").write_text("x")
    (tmp / "secret.txt").write_text("nope")
    mk = lambda st, lg: Deployer(reg, d.root, d.out_root, Audit(d.out_root / "audit.jsonl"), emulator=d.emulator, on_stage=st, on_log=lg)
    srv = make_server(reg, d.root, d.out_root, specs, mk, TOKEN, check_run=check_run, which=which or (lambda t: None), argo=argo)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1], tmp


def job(run, name):
    return next(j for j in run["jobs"] if j["name"] == name)


def test_auth_and_host_checks(harness):
    srv, port, _ = serve(harness, plan_of(rc("a", "aws_vpc", ["create"])))
    try:
        assert call(port, "/api/stacks", token="x")[0] == 403
        assert call(port, "/api/stacks", host="evil.example:80")[0] == 403
        assert call(port, "/api/stacks")[0] == 200 and call(port, "/")[0] == 200
    finally:
        srv.shutdown()


def test_full_pipeline_then_approval_and_apply(harness):
    srv, port, tmp = serve(harness, plan_of(rc("aws_vpc.main", "aws_vpc", ["create"])))
    try:
        assert call(port, "/api/apply", "POST", {"stack": "s", "confirm": "x"})[0] == 409
        assert call(port, "/api/run", "POST", {"stack": "s"})[0] == 202
        d = wait_for(port, lambda r: r["status"] in ("waiting", "failure"))
        r = d["run"]
        assert r["status"] == "waiting" and r["verdict"] == "auto"
        assert [j["status"] for j in r["jobs"]] == ["success", "success", "success", "waiting"]
        assert {s["status"] for s in job(r, "checks")["steps"]} == {"skipped"}
        plan_step = job(r, "plan")["steps"][2]
        assert plan_step["status"] == "success" and "terraform plan" in plan_step["log"]
        assert "verdict: AUTO" in job(r, "gate")["steps"][0]["log"]
        assert call(port, "/api/apply", "POST", {"stack": "s", "confirm": "nope"})[0] == 400
        sha = r["plan_sha"][:8]
        assert call(port, "/api/apply", "POST", {"stack": "s", "confirm": sha})[0] == 202
        d = wait_for(port, lambda r: r["status"] in ("success", "failure"))
        assert d["run"]["status"] == "success" and job(d["run"], "apply")["status"] == "success"
        assert all(s["status"] == "success" for s in job(d["run"], "apply")["steps"][:3])
        assert call(port, "/api/run?stack=s")[1]["matrix"] == [{"name": "s", "kind": "tf", "env": "dev", "status": "success"}]
    finally:
        srv.shutdown()


def test_blocking_check_stops_pipeline_and_annotates(harness):
    tflint = {"issues": [{"rule": {"name": "bad", "severity": "error"}, "message": "nope",
                          "range": {"filename": "main.tf", "start": {"line": 2}}}], "errors": []}
    fake = lambda argv, **kw: Result(2, json.dumps(tflint), "") if argv[0] == "tflint" else Result(0, "{}", "")
    srv, port, _ = serve(harness, plan_of(rc("a", "aws_vpc", ["create"])), env="staging", check_run=fake,
                         which=lambda t: "/x" if t == "tflint" else None)
    try:
        call(port, "/api/run", "POST", {"stack": "s"})
        d = wait_for(port, lambda r: r["status"] in ("waiting", "failure"))
        r = d["run"]
        assert r["status"] == "failure" and "Blocking static check" in r["error"]
        assert [j["status"] for j in r["jobs"]] == ["failure", "skipped", "skipped", "skipped"]
        assert d["checks"][1]["findings"][0]["line"] == 2
        tree = call(port, "/api/tree?stack=s")[1]
        files = []
        def walk(n):
            files.append(n) if n["type"] == "file" else [walk(c) for c in n["children"]]
        walk(tree["root"])
        main = next(f for f in files if f["name"] == "main.tf")
        assert main["findings"] == 1 and main["worst"] == 3
        assert not any(".terraform" in f["path"] for f in files)
        f = call(port, "/api/file?stack=s&path=stacks/s/main.tf")[1]
        assert f["ann"][0]["rule"] == "bad" and "aws_s3_bucket" in f["content"]
    finally:
        srv.shutdown()


def test_file_endpoint_blocks_traversal_and_hidden(harness):
    srv, port, _ = serve(harness, plan_of())
    try:
        for p in ("../secret.txt", "../../etc/passwd", "stacks/s/.terraform/junk.tf", "/etc/passwd"):
            assert call(port, f"/api/file?stack=s&path={p}")[0] == 400, p
    finally:
        srv.shutdown()


def test_denied_plan_fails_gate(harness):
    srv, port, _ = serve(harness, plan_of(rc("a", "aws_db_instance", ["delete"])))
    try:
        call(port, "/api/run", "POST", {"stack": "s"})
        r = wait_for(port, lambda r: r["status"] in ("waiting", "failure"))["run"]
        assert r["status"] == "failure" and job(r, "gate")["status"] == "failure" and job(r, "apply")["status"] == "skipped"
        assert "stateful-destroy" in r["error"]
    finally:
        srv.shutdown()


def test_busy_returns_409(harness):
    srv, port, _ = serve(harness, plan_of(rc("a", "aws_vpc", ["create"])))
    try:
        assert call(port, "/api/run", "POST", {"stack": "s"})[0] == 202
        codes = {call(port, "/api/run", "POST", {"stack": "s"})[0] for _ in range(3)}
        assert codes <= {409, 202}
        wait_for(port, lambda r: r["status"] != "running")
    finally:
        srv.shutdown()
