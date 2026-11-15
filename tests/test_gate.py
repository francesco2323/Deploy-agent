import json

from conftest import make_stack, plan_of, rc
from deploy_agent.gate import evaluate
from deploy_agent.spec import DeploySpec

S = DeploySpec("s")


def verdict(plan, env="dev", spec=S, **kw):
    return evaluate(plan, make_stack(env, **kw), spec)


def rules(d):
    return {f.rule for f in d.findings}


def test_noop():
    assert verdict(plan_of(rc("a", "aws_vpc", ["no-op"]))).verdict == "noop"


def test_dev_plain_create_is_auto():
    assert verdict(plan_of(rc("a", "aws_vpc", ["create"]))).verdict == "auto"


def test_staging_never_auto():
    assert verdict(plan_of(rc("a", "aws_vpc", ["create"])), env="staging").verdict == "needs_approval"


def test_dev_delete_needs_approval():
    assert verdict(plan_of(rc("a", "aws_subnet", ["delete"]))).verdict == "needs_approval"


def test_stateful_destroy_denied_even_in_dev():
    d = verdict(plan_of(rc("a", "aws_db_instance", ["delete", "create"])))
    assert d.verdict == "deny" and "stateful-destroy" in rules(d)


def test_stateful_destroy_allowed_with_flag_but_not_prod():
    p = plan_of(rc("a", "aws_s3_bucket", ["delete"]))
    spec = DeploySpec("s", allow_destroy=True)
    assert verdict(p, env="dev", spec=spec).verdict == "needs_approval"
    assert verdict(p, env="prod", spec=spec).verdict == "deny"


def test_iam_star_denied():
    doc = json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
    assert "iam-wildcard-action" in rules(verdict(plan_of(rc("p", "aws_iam_policy", ["create"], {"policy": doc}))))


def test_iam_passrole_star_denied():
    doc = json.dumps({"Statement": [{"Effect": "Allow", "Action": ["iam:PassRole"], "Resource": "*"}]})
    assert "iam-passrole-star" in rules(verdict(plan_of(rc("p", "aws_iam_role_policy", ["create"], {"policy": doc}))))


def test_iam_scoped_ok():
    doc = json.dumps({"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::b/*"}]})
    assert verdict(plan_of(rc("p", "aws_iam_policy", ["create"], {"policy": doc}))).verdict == "auto"


def test_trust_public_denied_unless_condition():
    bad = json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]})
    ok = json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole",
                                    "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-1"}}}]})
    assert "iam-trust-public" in rules(verdict(plan_of(rc("r", "aws_iam_role", ["create"], {"assume_role_policy": bad}))))
    assert "iam-trust-public" not in rules(verdict(plan_of(rc("r", "aws_iam_role", ["create"], {"assume_role_policy": ok}))))


def test_sg_open_ssh_denied_https_ok():
    ssh = {"ingress": [{"cidr_blocks": ["0.0.0.0/0"], "from_port": 22, "to_port": 22}]}
    web = {"ingress": [{"cidr_blocks": ["0.0.0.0/0"], "from_port": 443, "to_port": 443}]}
    assert "sg-open-ingress" in rules(verdict(plan_of(rc("g", "aws_security_group", ["create"], ssh))))
    assert "sg-open-ingress" not in rules(verdict(plan_of(rc("g", "aws_security_group", ["create"], web))))


def test_sg_rule_resource_variants():
    r1 = rc("g", "aws_security_group_rule", ["create"], {"type": "ingress", "cidr_blocks": ["0.0.0.0/0"], "from_port": 0, "to_port": 0})
    r2 = rc("g", "aws_vpc_security_group_ingress_rule", ["create"], {"cidr_ipv4": "0.0.0.0/0", "from_port": 5432, "to_port": 5432})
    assert verdict(plan_of(r1)).verdict == "deny" and verdict(plan_of(r2)).verdict == "deny"


def test_s3_public_and_encryption():
    assert verdict(plan_of(rc("b", "aws_s3_bucket_public_access_block", ["create"], {"block_public_acls": False}))).verdict == "deny"
    assert verdict(plan_of(rc("d", "aws_db_instance", ["create"], {"storage_encrypted": False}))).verdict == "deny"
    assert verdict(plan_of(rc("d", "aws_db_instance", ["create"], {"storage_encrypted": True}))).verdict == "auto"


def test_eks_public_endpoint_denied_outside_dev():
    after = {"vpc_config": [{"endpoint_public_access": True, "public_access_cidrs": ["0.0.0.0/0"]}]}
    p = plan_of(rc("e", "aws_eks_cluster", ["create"], after))
    assert verdict(p, env="dev").verdict == "auto"
    assert verdict(p, env="staging").verdict == "deny"


def test_blast_radius_escalates_dev():
    p = plan_of(*[rc(f"v{i}", "aws_vpc", ["create"]) for i in range(5)])
    assert verdict(p, max_changes=3).verdict == "needs_approval"


def test_vpc_and_tgw_replace_denied():
    assert verdict(plan_of(rc("v", "aws_vpc", ["delete", "create"]))).verdict == "deny"
    assert verdict(plan_of(rc("t", "aws_ec2_transit_gateway", ["delete"]))).verdict == "deny"


def test_vpc_tgw_create_auto_in_dev():
    p = plan_of(rc("v", "aws_vpc", ["create"]), rc("t", "aws_ec2_transit_gateway", ["create"], {"default_route_table_association": "enable"}))
    assert verdict(p).verdict == "auto"


def test_tgw_default_routing_flagged_outside_dev():
    p = plan_of(rc("t", "aws_ec2_transit_gateway", ["create"], {"default_route_table_propagation": "enable"}))
    d = verdict(p, env="staging")
    assert "tgw-flat-network" in rules(d) and d.verdict == "needs_approval"
