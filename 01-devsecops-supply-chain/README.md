# 01 · DevSecOps & Software Supply-Chain Security

**Proves:** Certified DevSecOps Professional (CDP) and Certified Software Supply Chain Security Expert (CSSE) skills: shifting security left and enforcing it as a build gate.

**Idea:** a build should *fail* on real security problems, not just print warnings that everyone ignores. This pipeline runs the standard scanners, then a single [`security_gate.py`](gate/security_gate.py) turns all their output into one reviewable pass/fail decision driven by [`policy.yaml`](policy.yaml).

## Pipeline

```
source ─► SAST (Bandit) ─┐
       ─► SCA (pip-audit)├─► reports (JSON) ─► security_gate.py ─► pass / FAIL
       ─► secrets (Gitleaks)                        ▲
build  ─► image (hardened Dockerfile)               │ policy.yaml
       ─► image scan (Trivy) ────────────┘   (fail_on_severity, ignore_unfixed, allowlist)
       ─► SBOM (Syft) + sign (Cosign)
```

## What each control does

| Stage | Tool | Catches |
|---|---|---|
| SAST | Bandit | Insecure code (shell injection, weak crypto, `assert` in prod) |
| SCA | pip-audit | Known CVEs in Python dependencies |
| Secrets | Gitleaks | Credentials committed to git |
| Image | Trivy | OS/library CVEs in the container image |
| SBOM | Syft + Cosign | A signed inventory of everything shipped, for provenance |
| Gate | `security_gate.py` | Applies the policy: HIGH+ fixable findings block; committed secrets always block |

The [Dockerfile](Dockerfile) is hardened too: slim base, pinned dependencies, a non-root user (UID 10001), no shell for that user, and a health check.

## The gate policy

Keeping the decision in [`policy.yaml`](policy.yaml) means the security bar is reviewed like code:

```yaml
fail_on_severity: HIGH   # block HIGH and CRITICAL
ignore_unfixed: true     # base-image CVEs with no fix are reported, not blocking
allowlist: []            # accepted risks, each with a ticket reference
```

A committed secret is always CRITICAL and always blocks — it must be revoked, not just deleted.

## Evidence

```bash
pip install -r ../requirements.txt
pytest -q     # gate + app tests: 14 passed
python gate/security_gate.py --policy policy.yaml \
  --bandit tests/fixtures/bandit.json --gitleaks tests/fixtures/gitleaks.json \
  --trivy tests/fixtures/trivy.json --pip-audit tests/fixtures/pip-audit.json
# -> RESULT: FAIL (blocks the shell-injection, the committed secret and the fixable CRITICAL CVE)
```

The GitHub Actions workflow in [`.github/workflows/security.yml`](../.github/workflows/security.yml) runs the whole pipeline on every push.

*Lab project. Fixtures are crafted sample reports so the gate's behaviour is fully testable offline.*
