import json
import re
import tomllib
from pathlib import Path

import pytest

from deploy_agent import __version__
from deploy_agent.audit import Audit
from deploy_agent.cli import main

ROOT = Path(__file__).resolve().parents[1]
SEMVER = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$")


def test_version_is_semver_and_single_sourced():
    assert SEMVER.match(__version__)
    proj = tomllib.loads((ROOT / "pyproject.toml").read_text())
    # a literal here would drift from the package: it must stay dynamic
    assert "version" not in proj["project"] and "version" in proj["project"]["dynamic"]
    assert proj["tool"]["setuptools"]["dynamic"]["version"]["attr"] == "deploy_agent.__version__"


def test_changelog_documents_the_current_version():
    log = (ROOT / "CHANGELOG.md").read_text()
    assert re.search(rf"^## \[{re.escape(__version__)}\]", log, re.M), "add a CHANGELOG entry before bumping"


def test_cli_reports_version(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0 and capsys.readouterr().out.strip() == f"deploy-agent {__version__}"


def test_audit_records_the_version_and_old_logs_still_verify(tmp_path):
    p = tmp_path / "a.jsonl"
    a = Audit(p)
    a.log("x", k=1)
    assert json.loads(p.read_text().splitlines()[0])["version"] == __version__
    assert Audit.verify(p)
    # a record written before versions existed (no "version" key) must still chain
    rec = {"ts": 1.0, "event": "old", "data": {}, "prev": json.loads(p.read_text().splitlines()[-1])["hash"]}
    from deploy_agent.audit import _h
    rec["hash"] = _h(rec)
    with p.open("a") as f:
        f.write(json.dumps(rec) + "\n")
    assert Audit.verify(p)
