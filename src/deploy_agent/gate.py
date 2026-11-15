"""Deterministic policy gate over `terraform show -json` output. No LLM in this path, ever.

Verdicts: deny | noop | auto | needs_approval
Replace with OPA/conftest or Checkov once the rule set outgrows this; keep the Decision contract.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from .spec import DeploySpec, Stack

STATEFUL = {
    "aws_db_instance", "aws_rds_cluster", "aws_s3_bucket", "aws_dynamodb_table", "aws_kms_key",
    "aws_eks_cluster", "aws_efs_file_system", "aws_elasticache_cluster", "aws_elasticache_replication_group",
    "aws_ebs_volume", "aws_secretsmanager_secret", "aws_route53_zone",
    # network core: delete/replace = outage for everything attached
    "aws_vpc", "aws_ec2_transit_gateway",
}
_IAM_POLICY_TYPES = {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"}
_BROAD_SERVICES = {"iam:*", "sts:*", "organizations:*", "*", "*:*"}
_WEB_PORTS = {80, 443}


@dataclass
class Finding:
    rule: str
    address: str
    severity: str  # deny | warn
    msg: str


@dataclass
class Decision:
    verdict: str
    findings: list[Finding] = field(default_factory=list)
    counts: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"verdict": self.verdict, "counts": self.counts, "findings": [f.__dict__ for f in self.findings]}


def _rcs(plan: dict) -> list[dict]:
    return plan.get("resource_changes") or []


def _actions(rc: dict) -> list[str]:
    return (rc.get("change") or {}).get("actions") or []


def _after(rc: dict) -> dict:
    return (rc.get("change") or {}).get("after") or {}


def _list(x):
    return x if isinstance(x, list) else ([] if x is None else [x])


def count_changes(plan: dict) -> dict:
    c = {"create": 0, "update": 0, "delete": 0, "replace": 0}
    for rc in _rcs(plan):
        a = _actions(rc)
        if "delete" in a and "create" in a:
            c["replace"] += 1
        elif "delete" in a:
            c["delete"] += 1
        elif "create" in a:
            c["create"] += 1
        elif "update" in a:
            c["update"] += 1
    return c


def _statements(doc):
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except ValueError:
            return None
    if not isinstance(doc, dict):
        return None
    s = doc.get("Statement", [])
    return [s] if isinstance(s, dict) else s


def _check_iam_doc(addr: str, doc, out: list[Finding]) -> None:
    stmts = _statements(doc)
    if stmts is None:
        if doc:
            out.append(Finding("iam-unparseable", addr, "warn", "policy document not parseable at plan time"))
        return
    for st in stmts:
        if st.get("Effect") != "Allow":
            continue
        acts = {a.lower() if a != "*" else a for a in _list(st.get("Action"))}
        res = _list(st.get("Resource"))
        if acts & {"*", "*:*", "iam:*", "sts:*", "organizations:*"}:
            out.append(Finding("iam-wildcard-action", addr, "deny", f"overbroad action(s): {sorted(acts & _BROAD_SERVICES)}"))
        if "iam:passrole" in acts and "*" in res:
            out.append(Finding("iam-passrole-star", addr, "deny", "iam:PassRole on Resource '*'"))


def _check_trust(addr: str, doc, out: list[Finding]) -> None:
    for st in _statements(doc) or []:
        p = st.get("Principal")
        wide = p == "*" or (isinstance(p, dict) and "*" in _list(p.get("AWS")))
        if st.get("Effect") == "Allow" and wide and not st.get("Condition"):
            out.append(Finding("iam-trust-public", addr, "deny", "assume-role trust allows any principal without Condition"))


def _open_cidr(cidrs, v6) -> bool:
    return "0.0.0.0/0" in _list(cidrs) or "::/0" in _list(v6)


def _port_ok(frm, to) -> bool:
    return frm is not None and frm == to and frm in _WEB_PORTS


def evaluate(plan: dict, stack: Stack, spec: DeploySpec) -> Decision:
    f: list[Finding] = []
    counts = count_changes(plan)
    total = sum(counts.values())

    for rc in _rcs(plan):
        t, addr, a, after = rc.get("type", ""), rc.get("address", ""), _actions(rc), _after(rc)

        if "delete" in a and t in STATEFUL:
            if spec.allow_destroy and stack.env != "prod":
                f.append(Finding("stateful-destroy", addr, "warn", f"{t} will be destroyed/replaced (allow_destroy set)"))
            else:
                f.append(Finding("stateful-destroy", addr, "deny", f"{t} would be destroyed/replaced"))

        if t in _IAM_POLICY_TYPES:
            _check_iam_doc(addr, after.get("policy"), f)
        if t == "aws_iam_role":
            _check_trust(addr, after.get("assume_role_policy"), f)
            for ip in _list(after.get("inline_policy")):
                _check_iam_doc(addr, (ip or {}).get("policy"), f)

        if t == "aws_security_group":
            for r in _list(after.get("ingress")):
                if _open_cidr(r.get("cidr_blocks"), r.get("ipv6_cidr_blocks")) and not _port_ok(r.get("from_port"), r.get("to_port")):
                    f.append(Finding("sg-open-ingress", addr, "deny", f"ingress open to world on {r.get('from_port')}-{r.get('to_port')}"))
        elif t == "aws_security_group_rule" and after.get("type") == "ingress":
            if _open_cidr(after.get("cidr_blocks"), after.get("ipv6_cidr_blocks")) and not _port_ok(after.get("from_port"), after.get("to_port")):
                f.append(Finding("sg-open-ingress", addr, "deny", "ingress open to world on non-web port"))
        elif t == "aws_vpc_security_group_ingress_rule":
            if _open_cidr(after.get("cidr_ipv4"), after.get("cidr_ipv6")) and not _port_ok(after.get("from_port"), after.get("to_port")):
                f.append(Finding("sg-open-ingress", addr, "deny", "ingress open to world on non-web port"))

        if t == "aws_s3_bucket_public_access_block":
            flags = ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")
            off = [k for k in flags if after.get(k) is False]
            if off:
                f.append(Finding("s3-public", addr, "deny", f"public access block disabled: {off}"))
        if t in {"aws_s3_bucket", "aws_s3_bucket_acl"} and after.get("acl") in {"public-read", "public-read-write"}:
            f.append(Finding("s3-public", addr, "deny", f"public ACL {after.get('acl')}"))

        if t in {"aws_db_instance", "aws_rds_cluster"} and after.get("storage_encrypted") is False:
            f.append(Finding("rds-unencrypted", addr, "deny", "storage_encrypted=false"))
        if t == "aws_ebs_volume" and after.get("encrypted") is False:
            f.append(Finding("ebs-unencrypted", addr, "deny", "encrypted=false"))

        if t == "aws_ec2_transit_gateway" and stack.env != "dev":
            on = [k for k in ("auto_accept_shared_attachments", "default_route_table_association",
                              "default_route_table_propagation") if after.get(k) == "enable"]
            if on:
                f.append(Finding("tgw-flat-network", addr, "warn", f"TGW defaults enabled ({on}): attachments get implicit any-to-any routing"))

        if t == "aws_eks_cluster" and stack.env != "dev":
            vc = (_list(after.get("vpc_config")) or [{}])[0] or {}
            if vc.get("endpoint_public_access") and "0.0.0.0/0" in _list(vc.get("public_access_cidrs") or ["0.0.0.0/0"]):
                f.append(Finding("eks-public-endpoint", addr, "deny", "public API endpoint open to 0.0.0.0/0 outside dev"))

    if total > stack.max_changes:
        f.append(Finding("blast-radius", "*", "warn", f"{total} changes > max_changes={stack.max_changes}"))

    if any(x.severity == "deny" for x in f):
        verdict = "deny"
    elif total == 0:
        verdict = "noop"
    elif stack.env == "dev" and counts["delete"] + counts["replace"] == 0 and not f:
        verdict = "auto"
    else:
        verdict = "needs_approval"
    return Decision(verdict, f, counts)


def render_summary(stack: Stack, plan: dict, d: Decision, plan_sha: str) -> str:
    c = d.counts
    lines = [
        f"### `{stack.name}` ({stack.env}) → **{d.verdict.upper()}**",
        f"plan `{plan_sha[:12]}` · +{c.get('create', 0)} ~{c.get('update', 0)} -{c.get('delete', 0)} ±{c.get('replace', 0)}",
        "",
    ]
    if d.findings:
        lines += ["| sev | rule | resource | detail |", "|---|---|---|---|"]
        lines += [f"| {x.severity} | {x.rule} | `{x.address}` | {x.msg} |" for x in d.findings]
        lines.append("")
    ch = [(r["address"], "/".join(_actions(r))) for r in _rcs(plan) if _actions(r) not in (["no-op"], ["read"])]
    if ch:
        lines.append("<details><summary>changes</summary>\n")
        lines += [f"- `{a}`: {act}" for a, act in ch[:50]]
        if len(ch) > 50:
            lines.append(f"- … {len(ch) - 50} more")
        lines.append("\n</details>")
    return "\n".join(lines)
