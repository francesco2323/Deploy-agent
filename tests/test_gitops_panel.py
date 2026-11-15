import json

import pytest

from conftest import plan_of, rc
from deploy_agent.gitops import Argo
from deploy_agent.runner import CmdError, Result
from test_ui import call

DOC = {
    "spec": {"source": {"repoURL": "git@x:o/r.git", "path": "apps/dev", "targetRevision": "main"},
             "destination": {"name": "in-cluster", "namespace": "platform"}},
    "status": {"sync": {"status": "Synced", "revision": "abc1234def"}, "health": {"status": "Healthy"},
               "operationState": {"phase": "Succeeded", "message": "synced", "finishedAt": "2026-11-15T10:00:00Z"},
               "resources": [{"kind": "Deployment", "name": "web", "namespace": "platform", "status": "Synced", "health": {"status": "Healthy"}}],
               "history": [{"id": 1, "revision": "aaa", "deployedAt": "t1"}, {"id": 2, "revision": "bbb", "deployedAt": "t2"}]},
}


def argo_with(doc):
    return Argo(run_fn=lambda argv, **kw: Result(0, json.dumps(doc), ""))


def test_detail_parsing():
    d = argo_with(DOC).detail("app1")
    assert d["sync"] == "Synced" and d["health"] == "Healthy" and d["path"] == "apps/dev"
    assert d["resources"][0]["name"] == "web" and [h["id"] for h in d["history"]] == [2, 1]


def test_wait_degraded_raises():
    bad = json.loads(json.dumps(DOC)); bad["status"]["health"]["status"] = "Degraded"
    with pytest.raises(CmdError):
        argo_with(bad).wait_healthy("app1", timeout=2, poll=0)


def test_ui_gitops_endpoint_and_argocd_step(harness):
    from test_ui import serve, wait_for, job
    srv, port, _ = serve(harness, plan_of(rc("aws_vpc.main", "aws_vpc", ["create"])), reg_edit={"argocd_app": "app1"}, argo=argo_with(DOC))
    try:
        g = call(port, "/api/gitops?stack=s")[1]
        assert g["configured"] and g["health"] == "Healthy" and g["app"] == "app1"
        call(port, "/api/run", "POST", {"stack": "s"})
        r = wait_for(port, lambda r: r["status"] in ("waiting", "failure"))["run"]
        assert [s["name"] for s in job(r, "apply")["steps"]][-1] == "argocd"
        call(port, "/api/apply", "POST", {"stack": "s", "confirm": r["plan_sha"][:8]})
        r = wait_for(port, lambda r: r["status"] in ("success", "failure"))["run"]
        assert r["status"] == "success" and job(r, "apply")["steps"][-1]["status"] == "success"
    finally:
        srv.shutdown()


def test_ui_gitops_not_configured(harness):
    from test_ui import serve
    srv, port, _ = serve(harness, plan_of())
    try:
        assert call(port, "/api/gitops?stack=s")[1] == {"configured": False}
    finally:
        srv.shutdown()
