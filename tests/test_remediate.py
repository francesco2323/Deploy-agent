import pytest

from deploy_agent import remediate as R
from deploy_agent.runner import Result
from deploy_agent.spec import Stack

TF = 'terraform {\n  required_providers {\n    aws = { source = "hashicorp/aws" }\n  }\n}\n\nresource "aws_s3_bucket" "logs" {\n\tbucket = "b1"\n}\n'


def stack():
    return Stack("s", "stacks/s", "dev", "000000000000", "eu-central-1")


def fmt_stub(argv, cwd=None, env=None, timeout=0, check=True):
    if argv[1] == "fmt":
        for p in cwd.rglob("*.tf"):
            p.write_text(p.read_text().replace("\t", "  "))
    return Result(0, "", "")


def res(**by):
    return [{"name": n, "status": "fail", "summary": "", "log": "", "findings": [
        {"file": "main.tf", "line": 1, "severity": "high", "rule": r, "msg": "m"} for r in rules]} for n, rules in by.items()]


@pytest.fixture
def root(tmp_path):
    d = tmp_path / "stacks" / "s"
    d.mkdir(parents=True)
    (d / "main.tf").write_text(TF)
    return tmp_path


def test_fmt_fix_previews_diff_and_only_changes_whitespace(root):
    fixes, _ = R.tf_fixes(stack(), root, res(fmt=["fmt"]), fmt_stub)
    f = fixes[0]
    assert f["id"] == "tf-fmt" and "-\tbucket" in f["files"][0]["diff"] and "+  bucket" in f["files"][0]["diff"]
    assert (root / "stacks/s/main.tf").read_text() == TF, "computing a fix must never write"


def test_s3_fixes_per_control_and_disappear_once_applied(root):
    r = res(trivy=["AVD-AWS-0086", "AVD-AWS-0090", "AVD-AWS-0088"])
    fixes, manual = R.tf_fixes(stack(), root, r, fmt_stub)
    assert {f["id"] for f in fixes} == {"s3-pab-logs", "s3-versioning-logs", "s3-sse-logs"} and not manual
    store = root / "out" / "fixes.json"
    with pytest.raises(R.FixError):  # three fixes touch one file: the 2nd, computed before the 1st landed, is stale
        R.apply_fix(root, "stacks/s", fixes[0], store)
        R.apply_fix(root, "stacks/s", fixes[1], store)
    for _ in range(3):
        cur, _ = R.tf_fixes(stack(), root, r, fmt_stub)
        if cur:
            R.apply_fix(root, "stacks/s", cur[0], store)
    txt = (root / "stacks/s/main.tf").read_text()
    assert 'aws_s3_bucket_public_access_block" "logs"' in txt and "restrict_public_buckets = true" in txt and 'status = "Enabled"' in txt
    assert R.tf_fixes(stack(), root, r, fmt_stub)[0] == []


def test_required_version_and_unknown_findings_stay_manual(root):
    fixes, manual = R.tf_fixes(stack(), root, res(tflint=["terraform_required_version", "terraform_unused_declarations"]), fmt_stub)
    assert [f["id"] for f in fixes] == ["tf-required-version"]
    assert [m["rule"] for m in manual] == ["terraform_unused_declarations"]
    R.apply_fix(root, "stacks/s", fixes[0], root / "o.json")
    assert 'required_version = ">= 1.5.0"' in (root / "stacks/s/main.tf").read_text()


def test_apply_is_compare_and_swap_and_confined(root):
    fixes, _ = R.tf_fixes(stack(), root, res(fmt=["fmt"]), fmt_stub)
    (root / "stacks/s/main.tf").write_text(TF + "# edited meanwhile\n")
    with pytest.raises(R.FixError, match="changed since"):
        R.apply_fix(root, "stacks/s", fixes[0], root / "o.json")
    evil = R.make_fix("x", "tf", "fmt", "t", "w", [], [("stacks/other/x.tf", None, "boom")])
    with pytest.raises(R.FixError, match="outside"):
        R.apply_fix(root, "stacks/s", evil, root / "o.json")
    evil = R.make_fix("x", "tf", "fmt", "t", "w", [], [("stacks/s/../../x.tf", None, "boom")])
    with pytest.raises(R.FixError):
        R.apply_fix(root, "stacks/s", evil, root / "o.json")
    assert not (root / "x.tf").exists()


def test_undo_restores_and_refuses_to_clobber_later_edits(root):
    store = root / "o.json"
    fixes, _ = R.tf_fixes(stack(), root, res(fmt=["fmt"]), fmt_stub)
    R.apply_fix(root, "stacks/s", fixes[0], store)
    assert R.history(store)[0]["id"] == "tf-fmt"
    assert R.undo_last(root, store) == {"undone": "Format Terraform files (terraform fmt)"}
    assert (root / "stacks/s/main.tf").read_text() == TF and R.history(store) == []
    R.apply_fix(root, "stacks/s", R.tf_fixes(stack(), root, res(fmt=["fmt"]), fmt_stub)[0][0], store)
    (root / "stacks/s/main.tf").write_text("mine")
    with pytest.raises(R.FixError, match="edited after"):
        R.undo_last(root, store)
    assert (root / "stacks/s/main.tf").read_text() == "mine"
    with pytest.raises(R.FixError):
        R.undo_last(root, root / "empty.json")
