import json

import pytest

from conftest import plan_of, rc
from deploy_agent.audit import Audit
from deploy_agent.gitops import set_values
from deploy_agent.runner import CmdError, run
from deploy_agent.spec import DeploySpec, Registry, SpecError, Stack, validate_spec
from deploy_agent.workflow import ApprovalRequired, IntegrityError, PolicyDenied

VPC = plan_of(rc("aws_vpc.main", "aws_vpc", ["create"]))


def test_dev_auto_plan_then_apply(harness):
    d, reg, log, tmp = harness(VPC)
    art = d.plan(DeploySpec("s", {"node_desired_size": "3"}))
    assert art.decision.verdict == "auto"
    res = d.apply("s")
    assert res["status"] == "applied" and res["outputs"] == {"cluster_name": "dev"}
    calls = log.read_text()
    assert "-var node_desired_size=3" in calls and "apply -input=false" in calls
    assert Audit.verify(tmp / "out" / "audit.jsonl")


def test_emulator_override_cleaned_up(harness):
    d, reg, log, tmp = harness(VPC)
    d.plan(DeploySpec("s"))
    assert not list((tmp / "root").rglob("zz_floci_override.tf"))


def test_tampered_plan_refused(harness):
    d, reg, log, tmp = harness(VPC)
    d.plan(DeploySpec("s"))
    (tmp / "out" / "s" / "tfplan").write_text(json.dumps(plan_of(rc("x", "aws_vpc", ["create"]))))
    with pytest.raises(IntegrityError):
        d.apply("s")
    assert not any(l.startswith("apply") for l in log.read_text().splitlines())


def test_tampered_spec_refused(harness):
    d, reg, log, tmp = harness(VPC)
    d.plan(DeploySpec("s", {"node_desired_size": "3"}))
    sp = tmp / "out" / "s" / "spec.json"
    sp.write_text(json.dumps({"stack": "s", "vars": {"node_desired_size": "99"}, "allow_destroy": False}))
    with pytest.raises(IntegrityError):
        d.apply("s")


def test_needs_approval_blocks_without_approver(harness):
    d, reg, log, tmp = harness(plan_of(rc("a", "aws_subnet", ["delete"])))
    d.plan(DeploySpec("s"))
    with pytest.raises(ApprovalRequired):
        d.apply("s")
    assert d.apply("s", approved_by="fle")["status"] == "applied"


def test_denied_plan_never_applies(harness):
    d, reg, log, tmp = harness(plan_of(rc("a", "aws_db_instance", ["delete"])))
    art = d.plan(DeploySpec("s"))
    assert art.decision.verdict == "deny"
    with pytest.raises(PolicyDenied):
        d.apply("s", approved_by="fle")
    assert not any(l.startswith("apply") for l in log.read_text().splitlines())


def test_apply_regates_even_if_decision_json_forged(harness):
    d, reg, log, tmp = harness(plan_of(rc("a", "aws_db_instance", ["delete"])))
    d.plan(DeploySpec("s"))
    (tmp / "out" / "s" / "decision.json").write_text(json.dumps({"verdict": "auto"}))
    with pytest.raises(PolicyDenied):
        d.apply("s")


def test_noop(harness):
    d, reg, log, tmp = harness(plan_of(rc("a", "aws_vpc", ["no-op"])), plan_rc=0)
    d.plan(DeploySpec("s"))
    assert d.apply("s") == {"status": "noop"}


def test_spec_validation():
    st = Stack("s", "p", "prod", "1", "r", allowed_vars=("a",))
    reg = Registry({"s": st})
    with pytest.raises(SpecError):
        validate_spec({"stack": "nope"}, reg)
    with pytest.raises(SpecError):
        validate_spec({"stack": "s", "vars": {"b": "x"}}, reg)
    with pytest.raises(SpecError):
        validate_spec({"stack": "s", "vars": {"a": "x; rm -rf /"}}, reg)
    with pytest.raises(SpecError):
        validate_spec({"stack": "s", "allow_destroy": True}, reg)
    assert validate_spec({"stack": "s", "vars": {"a": "ok-1"}}, reg)[0].vars == {"a": "ok-1"}


def test_runner_allowlist():
    with pytest.raises(CmdError):
        run(["bash", "-c", "true"])


def test_audit_tamper_detected(tmp_path):
    a = Audit(tmp_path / "a.jsonl")
    a.log("one"); a.log("two")
    assert Audit.verify(tmp_path / "a.jsonl")
    p = tmp_path / "a.jsonl"
    p.write_text(p.read_text().replace('"one"', '"ONE"'))
    assert not Audit.verify(p)


def test_gitops_values_allowlist(tmp_path):
    f = tmp_path / "values.yaml"
    f.write_text("image:\n  tag: old\nreplicas: 1\n")
    set_values(f, {"image.tag": "v2"}, {"image.tag"})
    assert "tag: v2" in f.read_text()
    with pytest.raises(CmdError):
        set_values(f, {"replicas": 9}, {"image.tag"})
