import json
import os
import stat
from pathlib import Path

import pytest

from deploy_agent.audit import Audit
from deploy_agent.spec import Registry, Stack
from deploy_agent.workflow import Deployer

FAKE_TF = """#!/bin/sh
echo "$@" >> "$TF_FAKE_LOG"
case "$1" in
  init|validate) exit 0;;
  plan) for a in "$@"; do case "$a" in -out=*) out="${a#-out=}";; esac; done
        cp "$TF_FAKE_PLAN_JSON" "$out"; exit ${TF_FAKE_PLAN_RC:-2};;
  show) for a; do last=$a; done; cat "$last"; exit 0;;
  apply) exit 0;;
  output) echo '{"cluster_name":{"value":"dev","sensitive":false}}'; exit 0;;
esac
"""


def rc(addr, typ, actions, after=None):
    return {"address": addr, "type": typ, "change": {"actions": actions, "after": after or {}}}


def plan_of(*rcs):
    return {"format_version": "1.2", "resource_changes": list(rcs)}


def make_stack(env="dev", max_changes=25):
    return Stack("s", "stacks/s", env, "000000000000", "eu-central-1",
                 allowed_vars=("node_desired_size",), max_changes=max_changes)


@pytest.fixture
def harness(tmp_path, monkeypatch):
    def build(plan: dict, env="dev", plan_rc=2):
        bindir = tmp_path / "bin"
        bindir.mkdir(exist_ok=True)
        tf = bindir / "terraform"
        tf.write_text(FAKE_TF)
        tf.chmod(tf.stat().st_mode | stat.S_IEXEC)
        pj = tmp_path / "plan.json"
        pj.write_text(json.dumps(plan))
        log = tmp_path / "tf.log"
        log.write_text("")
        monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")
        monkeypatch.setenv("TF_FAKE_PLAN_JSON", str(pj))
        monkeypatch.setenv("TF_FAKE_LOG", str(log))
        monkeypatch.setenv("TF_FAKE_PLAN_RC", str(plan_rc))
        monkeypatch.delenv("GITHUB_SHA", raising=False)
        stack = make_stack(env)
        (tmp_path / "root" / stack.path).mkdir(parents=True, exist_ok=True)
        reg = Registry({"s": stack})
        d = Deployer(reg, tmp_path / "root", tmp_path / "out", Audit(tmp_path / "out" / "audit.jsonl"),
                     emulator="http://127.0.0.1:4566")
        return d, reg, log, tmp_path
    return build
