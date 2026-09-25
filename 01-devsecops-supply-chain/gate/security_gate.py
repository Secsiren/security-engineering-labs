"""Security gate: turn scanner reports into one pass/fail decision.

Reads the JSON reports produced in CI (Bandit SAST, pip-audit SCA, Gitleaks
secrets, Trivy container scan), normalises every finding into one format,
applies the thresholds in policy.yaml and exits non-zero when the build must
stop. Keeping the decision in code (not in ten separate CI steps) makes the
policy reviewable, testable and identical on every pipeline.

Usage:
    python gate/security_gate.py --policy policy.yaml \
        --bandit bandit.json --pip-audit pip-audit.json \
        --gitleaks gitleaks.json --trivy trivy.json
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

SEVERITY_ORDER = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass(frozen=True)
class Finding:
    tool: str
    rule: str
    severity: str
    location: str
    fixable: bool = True

    def rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)


def _load(path: str | None):
    if not path:
        return None
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return None
    return json.loads(p.read_text())


def parse_bandit(data) -> list[Finding]:
    if not data:
        return []
    return [
        Finding("bandit", r.get("test_id", "?"), r.get("issue_severity", "UNKNOWN").upper(),
                f"{r.get('filename')}:{r.get('line_number')}")
        for r in data.get("results", [])
    ]


def parse_pip_audit(data) -> list[Finding]:
    # pip-audit JSON has no severity field; any known vulnerability in a
    # dependency is treated as HIGH, and "fixable" if a fixed version exists.
    if not data:
        return []
    deps = data.get("dependencies", data if isinstance(data, list) else [])
    out = []
    for dep in deps:
        for v in dep.get("vulns", []):
            out.append(Finding("pip-audit", v.get("id", "?"), "HIGH",
                               f"{dep.get('name')}=={dep.get('version')}",
                               fixable=bool(v.get("fix_versions"))))
    return out


def parse_gitleaks(data) -> list[Finding]:
    # Any committed secret is CRITICAL: it must be revoked, not just removed.
    if not data:
        return []
    return [
        Finding("gitleaks", f.get("RuleID", "secret"), "CRITICAL",
                f"{f.get('File')}:{f.get('StartLine')}")
        for f in data
    ]


def parse_trivy(data) -> list[Finding]:
    if not data:
        return []
    out = []
    for result in data.get("Results", []) or []:
        for v in result.get("Vulnerabilities", []) or []:
            out.append(Finding("trivy", v.get("VulnerabilityID", "?"),
                               v.get("Severity", "UNKNOWN").upper(),
                               f"{v.get('PkgName')}@{v.get('InstalledVersion')}",
                               fixable=bool(v.get("FixedVersion"))))
    return out


def evaluate(findings: list[Finding], policy: dict) -> tuple[bool, list[Finding]]:
    """Return (passed, blocking_findings) according to the policy."""
    fail_at = SEVERITY_ORDER[policy.get("fail_on_severity", "HIGH").upper()]
    ignore_unfixed = policy.get("ignore_unfixed", True)
    allow = set(policy.get("allowlist", []) or [])
    blocking = [
        f for f in findings
        if f.rank() >= fail_at
        and f.rule not in allow
        and not (ignore_unfixed and not f.fixable)
    ]
    return (not blocking, blocking)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--policy", required=True)
    ap.add_argument("--bandit")
    ap.add_argument("--pip-audit", dest="pip_audit")
    ap.add_argument("--gitleaks")
    ap.add_argument("--trivy")
    args = ap.parse_args(argv)

    policy = yaml.safe_load(Path(args.policy).read_text()) or {}
    findings = (parse_bandit(_load(args.bandit)) + parse_pip_audit(_load(args.pip_audit))
                + parse_gitleaks(_load(args.gitleaks)) + parse_trivy(_load(args.trivy)))
    passed, blocking = evaluate(findings, policy)

    print(f"Security gate: {len(findings)} findings, {len(blocking)} blocking "
          f"(fail_on={policy.get('fail_on_severity', 'HIGH')}, "
          f"ignore_unfixed={policy.get('ignore_unfixed', True)})")
    for f in sorted(blocking, key=lambda x: -x.rank()):
        print(f"  BLOCK [{f.severity}] {f.tool} {f.rule} at {f.location}")
    print("RESULT:", "PASS" if passed else "FAIL")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
