"""Guards for the "no real cloud, nothing billable" rule. If you need real AWS later, change this deliberately."""
from pathlib import Path

import yaml

WF = Path(__file__).resolve().parents[1] / ".github" / "workflows"


def _all():
    return {p.name: p.read_text() for p in sorted(WF.glob("*.yml"))}


def test_workflows_are_valid_yaml():
    for name, text in _all().items():
        assert isinstance(yaml.safe_load(text), dict), name


def test_no_workflow_can_reach_real_aws():
    for name, text in _all().items():
        assert "configure-aws-credentials" not in text, name
        assert "id-token: write" not in text, name          # no OIDC federation
        assert "role-to-assume" not in text, name


def test_terraform_runs_only_against_the_emulator():
    text = _all()["floci.yml"]
    assert "floci/floci" in text and "DEPLOY_AGENT_EMULATOR: http://localhost:4566" in text


def test_only_the_release_workflow_publishes_images_and_never_latest():
    for name, text in _all().items():
        if name != "release.yml":
            assert "push: true" not in text and "docker/login-action" not in text, name
    rel = _all()["release.yml"]
    code = "\n".join(l.split("#")[0] for l in rel.splitlines())
    assert ":latest" not in code
    assert yaml.safe_load(rel)[True]["push"]["tags"]  # only on tags
