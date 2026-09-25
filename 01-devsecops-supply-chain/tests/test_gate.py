"""The gate is the control, so it gets its own regression tests."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "gate"))
import security_gate as g  # noqa: E402

FIX = Path(__file__).parent / "fixtures"
POLICY = {"fail_on_severity": "HIGH", "ignore_unfixed": True, "allowlist": []}


def load(name):
    return json.loads((FIX / name).read_text())


def test_bandit_high_finding_blocks():
    findings = g.parse_bandit(load("bandit.json"))
    passed, blocking = g.evaluate(findings, POLICY)
    assert not passed
    assert [f.rule for f in blocking] == ["B602"]  # shell=True command injection


def test_bandit_low_finding_alone_passes():
    findings = [f for f in g.parse_bandit(load("bandit.json")) if f.severity == "LOW"]
    assert g.evaluate(findings, POLICY)[0]


def test_committed_secret_is_always_critical():
    findings = g.parse_gitleaks(load("gitleaks.json"))
    assert findings and all(f.severity == "CRITICAL" for f in findings)
    assert not g.evaluate(findings, POLICY)[0]


def test_trivy_unfixed_cve_reported_but_not_blocking():
    findings = g.parse_trivy(load("trivy.json"))
    passed, blocking = g.evaluate(findings, POLICY)
    assert {f.rule for f in blocking} == {"CVE-2099-0001"}  # fixable CRITICAL only
    assert any(f.rule == "CVE-2099-0002" and not f.fixable for f in findings)


def test_strict_policy_blocks_unfixed_too():
    findings = g.parse_trivy(load("trivy.json"))
    strict = {**POLICY, "ignore_unfixed": False}
    assert len(g.evaluate(findings, strict)[1]) == 2


def test_pip_audit_vuln_with_fix_blocks():
    findings = g.parse_pip_audit(load("pip-audit.json"))
    passed, blocking = g.evaluate(findings, POLICY)
    assert not passed and blocking[0].location == "requests==2.19.0"


def test_allowlisted_risk_does_not_block():
    findings = g.parse_pip_audit(load("pip-audit.json"))
    policy = {**POLICY, "allowlist": [findings[0].rule]}
    assert g.evaluate(findings, policy)[0]


def test_missing_or_empty_reports_are_safe(tmp_path):
    empty = tmp_path / "empty.json"
    empty.write_text("")
    assert g._load(str(empty)) is None
    assert g._load(str(tmp_path / "nope.json")) is None


def test_cli_exit_codes(tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text("fail_on_severity: HIGH\nignore_unfixed: true\n")
    assert g.main(["--policy", str(policy), "--bandit", str(FIX / "bandit.json")]) == 1
    clean = tmp_path / "clean.json"
    clean.write_text(json.dumps({"results": []}))
    assert g.main(["--policy", str(policy), "--bandit", str(clean)]) == 0
