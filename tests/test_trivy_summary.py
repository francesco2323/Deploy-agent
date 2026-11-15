import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "trivy_summary.py"


def run(tmp_path, vulns):
    rep = tmp_path / "t.json"
    rep.write_text(json.dumps({"Results": [{"Target": "x", "Vulnerabilities": vulns}]}))
    out = tmp_path / "s.md"
    r = subprocess.run([sys.executable, str(SCRIPT), str(rep), str(out)], capture_output=True, text=True)
    return r.returncode, out.read_text()


def v(sev, fixed, pkg="openssl"):
    return {"VulnerabilityID": "CVE-1", "PkgName": pkg, "InstalledVersion": "1.0", "FixedVersion": fixed,
            "Severity": sev, "Title": "t|itle"}


def test_fixable_critical_fails_and_is_listed(tmp_path):
    rc, md = run(tmp_path, [v("CRITICAL", "1.1")])
    assert rc == 1 and "| CRITICAL | `openssl` | 1.0 | 1.1 |" in md and "1 fixable" in md


def test_unfixed_findings_are_shown_but_do_not_fail(tmp_path):
    rc, md = run(tmp_path, [v("HIGH", "")])
    assert rc == 0 and "no fix yet" in md


def test_medium_and_clean_reports_pass(tmp_path):
    assert run(tmp_path, [v("MEDIUM", "2.0")])[0] == 0
    rc, md = run(tmp_path, [])
    assert rc == 0 and "No HIGH or CRITICAL" in md


def test_critical_sorts_before_high_and_pipes_are_escaped(tmp_path):
    rc, md = run(tmp_path, [v("HIGH", "1", "a"), v("CRITICAL", "1", "b")])
    assert md.index("CRITICAL") < md.index("| HIGH") and "t\\|itle" in md


def test_unfixed_are_grouped_by_cve_in_a_collapsed_block_below_the_fixable_table(tmp_path):
    vs = [v("HIGH", "", "libblkid1"), v("HIGH", "", "mount"), v("HIGH", "9", "urllib3")]
    rc, md = run(tmp_path, vs)
    assert rc == 1 and "1 distinct CVEs with no fix yet (2 package findings)" in md
    assert "`libblkid1`, `mount`" in md and md.count("| CVE-1 |") == 1
    assert md.index("`urllib3`") < md.index("<details>")
