import json

import pytest

from deploy_agent import inventory
from deploy_agent.audit import Audit
from deploy_agent.runner import Result
from fakedocker import FakeDocker


def test_containers_list_puts_agent_containers_first_and_flags_them():
    r = inventory.listing("containers", FakeDocker())
    assert r["ok"] and [i["name"] for i in r["items"]] == ["deploy-agent-sample-1700000000", "web"]
    assert [i["agent"] for i in r["items"]] == [True, False]


def test_volumes_and_networks_parse():
    assert inventory.listing("volumes", FakeDocker())["items"] == [{"name": "pgdata", "driver": "local", "scope": "local"}]
    assert [n["name"] for n in inventory.listing("networks", FakeDocker())["items"]] == ["bridge", "host"]


def test_missing_or_stopped_docker_is_a_message_not_a_crash():
    def boom(*a, **k):
        raise FileNotFoundError("docker")
    assert not inventory.listing("containers", boom)["ok"]
    down = lambda *a, **k: Result(1, "", "Cannot connect to the Docker daemon")
    r = inventory.listing("volumes", down)
    assert not r["ok"] and "Cannot connect" in r["error"] and r["items"] == []


def test_listing_is_read_only():
    f = FakeDocker()
    for k in ("containers", "volumes", "networks"):
        inventory.listing(k, f)
    assert all(c[1] in ("ps", "volume", "network") and "rm" not in c for c in f.calls)


@pytest.mark.parametrize("name", ["web", "deploy-agent", "deploy-agent-", "deploy-agent-a b", "deploy-agent-a;rm", "../deploy-agent-x", "", "Deploy-agent-x"])
def test_only_agent_containers_can_be_removed(name):
    f = FakeDocker()
    with pytest.raises(ValueError):
        inventory.remove_container(name, f)
    assert not f.subs("rm")


def test_agent_container_is_removed_with_a_single_forced_rm():
    f = FakeDocker()
    assert inventory.remove_container("deploy-agent-a-17", f) == {"removed": "deploy-agent-a-17"}
    assert f.subs("rm") == [["docker", "rm", "-f", "deploy-agent-a-17"]]


def test_events_merge_filter_and_verify(tmp_path):
    a, b = tmp_path / "audit.jsonl", tmp_path / "ui.jsonl"
    Audit(a).log("plan", stack="dev", n=3)
    Audit(b).log("fix.applied", target="sample")
    r = inventory.read_events({"deploy": a, "dashboard": b})
    assert r["verified"] == {"deploy": True, "dashboard": True} and r["count"] == 2
    assert {i["event"] for i in r["items"]} == {"plan", "fix.applied"} and r["items"][0]["version"]
    assert [i["event"] for i in inventory.read_events({"deploy": a, "dashboard": b}, needle="sample")["items"]] == ["fix.applied"]


def test_missing_log_is_none_and_tampering_is_reported(tmp_path):
    a = tmp_path / "audit.jsonl"
    assert inventory.read_events({"deploy": a})["verified"] == {"deploy": None}
    Audit(a).log("plan", stack="dev")
    rec = json.loads(a.read_text())
    rec["data"]["stack"] = "prod"
    a.write_text(json.dumps(rec) + "\n")
    assert inventory.read_events({"deploy": a})["verified"] == {"deploy": False}
    a.write_text("not json\n")
    assert inventory.read_events({"deploy": a})["verified"] == {"deploy": False}
