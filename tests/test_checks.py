import json

from deploy_agent.checks import mode_for, run_check
from deploy_agent.runner import Result
from deploy_agent.spec import Stack

TFLINT = {"issues": [{"rule": {"name": "aws_instance_invalid_type", "severity": "error"}, "message": "bad type",
                      "range": {"filename": "main.tf", "start": {"line": 7}}},
                     {"rule": {"name": "terraform_unused", "severity": "warning"}, "message": "unused",
                      "range": {"filename": "variables.tf", "start": {"line": 2}}}], "errors": []}
TRIVY = {"Results": [{"Target": "main.tf", "Misconfigurations": [
    {"AVDID": "AVD-AWS-0086", "Severity": "HIGH", "Title": "No public access block", "CauseMetadata": {"StartLine": 12}},
    {"AVDID": "AVD-AWS-0090", "Severity": "MEDIUM", "Title": "No versioning", "CauseMetadata": {"StartLine": 12}}]}]}
CHECKOV = [{"results": {"failed_checks": [{"check_id": "CKV_AWS_18", "check_name": "access logging", "file_path": "/main.tf",
                                          "file_line_range": [10, 14], "resource": "aws_s3_bucket.t"}]}}]
have = lambda t: "/usr/bin/" + t
none = lambda t: None


def rn(out, rc=0, err=""):
    return lambda argv, **kw: Result(rc, out if isinstance(out, str) else json.dumps(out), err)


def test_skipped_when_not_installed():
    r = run_check("trivy", ".", "block", which=none)
    assert r.status == "skipped" and "brew install trivy" in r.log


def test_mode_off():
    assert run_check("tflint", ".", "off", which=have).status == "skipped"


def test_tflint_error_fails_and_warn_mode_downgrades():
    r = run_check("tflint", ".", "block", run_fn=rn(TFLINT, 2), which=have)
    assert r.status == "fail" and r.findings[0]["file"] == "main.tf" and r.findings[0]["line"] == 7
    assert run_check("tflint", ".", "warn", run_fn=rn(TFLINT, 2), which=have).status == "warn"


def test_trivy_high_fails_medium_only_warns():
    assert run_check("trivy", ".", "block", run_fn=rn(TRIVY), which=have).status == "fail"
    only_med = {"Results": [{"Target": "main.tf", "Misconfigurations": [TRIVY["Results"][0]["Misconfigurations"][1]]}]}
    assert run_check("trivy", ".", "block", run_fn=rn(only_med), which=have).status == "warn"
    assert run_check("trivy", ".", "block", run_fn=rn({}), which=have).status == "pass"


def test_checkov_path_normalised():
    r = run_check("checkov", ".", "block", run_fn=rn(CHECKOV, 1), which=have)
    assert r.status == "fail" and r.findings[0]["file"] == "main.tf" and r.findings[0]["line"] == 10


def test_fmt_lists_files():
    r = run_check("fmt", ".", "block", run_fn=rn("main.tf\n--- old/main.tf\n+++ new/main.tf\n", 3), which=have)
    assert r.status == "fail" and [f["file"] for f in r.findings] == ["main.tf"]
    assert run_check("fmt", ".", "block", run_fn=rn("", 0), which=have).status == "pass"


def test_tool_crash_is_error_not_pass():
    r = run_check("trivy", ".", "block", run_fn=rn("boom", 1, "db download failed"), which=have)
    assert r.status == "error"
    assert run_check("trivy", ".", "block", run_fn=rn("not json"), which=have).status == "error"


def test_default_modes():
    dev = Stack("a", "p", "dev", "1", "r"); prod = Stack("b", "p", "prod", "1", "r", checks={"trivy": "warn"})
    assert mode_for(dev, "tflint") == "warn" and mode_for(prod, "tflint") == "block" and mode_for(prod, "trivy") == "warn"
