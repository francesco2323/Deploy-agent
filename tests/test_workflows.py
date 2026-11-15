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


def test_every_action_is_pinned_to_a_full_commit_sha():
    import re
    for name, text in _all().items():
        for ref in re.findall(r"uses:\s*(\S+)", text):
            assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", ref), f"{name}: {ref} (tags are mutable; pin a SHA)"


def test_trivy_actions_are_never_the_hijacked_tags_and_the_binary_is_pinned():
    # March 2026: 76 of 77 trivy-action tags and every setup-trivy tag but v0.2.6 were force-pushed to malware; binary v0.69.4 was malicious
    text = "\n".join(_all().values())
    assert "trivy-action@57a97c7e7821a5776cebc9bb87c984fa69cba8f1" in text      # v0.35.0
    assert "setup-trivy@3fb12ec12f41e471780db15c232d5dd185dcb514" in text       # v0.2.6
    assert "v0.69.4" not in text.replace("v0.69.4 was malicious", "")
    assert text.count("version: v0.69.3") >= 3
