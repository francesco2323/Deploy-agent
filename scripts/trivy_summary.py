#!/usr/bin/env python3
"""Turn `trivy image --format json` output into a Markdown table and a pass/fail gate.

Usage: trivy_summary.py trivy.json [summary.md]   (summary defaults to $GITHUB_STEP_SUMMARY, else stdout)
Gate: exit 1 if any HIGH/CRITICAL finding has a fixed version available. Unfixed findings are listed but never fail.
"""
from __future__ import annotations

import json
import os
import sys

BLOCK = ("CRITICAL", "HIGH")
ORDER = {s: i for i, s in enumerate(BLOCK)}


def findings(report: dict) -> list[dict]:
    out = []
    for res in report.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            if v.get("Severity") in BLOCK:
                out.append({"target": res.get("Target", ""), "id": v.get("VulnerabilityID", ""),
                            "pkg": v.get("PkgName", ""), "installed": v.get("InstalledVersion", ""),
                            "fixed": v.get("FixedVersion") or "", "sev": v["Severity"], "title": v.get("Title", "")})
    return sorted(out, key=lambda f: (ORDER[f["sev"]], f["pkg"], f["id"]))


def render(found: list[dict]) -> tuple[str, int]:
    fixable = [f for f in found if f["fixed"]]
    lines = ["## Trivy image scan", ""]
    if not found:
        lines.append("No HIGH or CRITICAL vulnerabilities found.")
    else:
        lines += [f"**{len(fixable)} fixable** and {len(found) - len(fixable)} without a fix (HIGH/CRITICAL). "
                  "Only fixable findings fail the check.", "",
                  "| Severity | Package | Installed | Fixed in | ID | Title |", "|---|---|---|---|---|---|"]
        for f in found:
            title = f["title"].replace("|", "\\|")[:90]
            lines.append(f"| {f['sev']} | `{f['pkg']}` | {f['installed']} | {f['fixed'] or 'no fix yet'} | {f['id']} | {title} |")
        if fixable:
            lines += ["", "Fix: bump the base image or the package named above, rebuild, re-run."]
    return "\n".join(lines) + "\n", (1 if fixable else 0)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    md, rc = render(findings(json.load(open(argv[1]))))
    dest = argv[2] if len(argv) > 2 else os.environ.get("GITHUB_STEP_SUMMARY")
    if dest:
        with open(dest, "a") as f:
            f.write(md)
    print(md)
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
