# Security Engineering Labs

Four hands-on security engineering projects by **Beatrice Mwangi** — each with working code, tests that prove the controls, and a written design. Together they cover the application, pipeline, cloud-native and OT sides of the field, and back up my certifications with runnable evidence.

[![CI](https://github.com/OWNER/REPO/actions/workflows/security.yml/badge.svg)](../../actions)

| # | Project | Skills / certifications it evidences | Highlights |
|---|---|---|---|
| 01 | [DevSecOps & Supply-Chain Security](01-devsecops-supply-chain) | CDP, CSSE | SAST/SCA/secret/image scanning behind one policy-driven **security gate**; hardened Dockerfile; SBOM + signing |
| 02 | [Threat Model + API Security](02-threat-model-api-security) | CTMP, CASP | STRIDE threat model of an API, then automated **OWASP API Top 10** attack tests (vulnerable vs. fixed) |
| 03 | [Container & Kubernetes Security](03-container-k8s-security) | CCSE, CCNSE | Pod Security "restricted", default-deny networking, a **policy-as-code** manifest checker, Kyverno admission policies |
| 04 | [OT / ICS Security](04-ot-ics-security) | CSSA, ICS workshop | Passive **Modbus/TCP monitor** enforcing a policy derived from an **IEC 62443** zone-and-conduit design |

## How each project is structured

```
docs/ or design    ->  the threat/architecture reasoning
code               ->  the control (Python, FastAPI, k8s, policy-as-code)
tests/             ->  one test per control, run in CI
README.md          ->  what it proves and how to run it
```

## Run everything

```bash
pip install -r requirements.txt
for d in 0*/; do (cd "$d" && python -m pytest -q); done
```

All suites run on every push via [`.github/workflows/security.yml`](.github/workflows/security.yml).

## About me

Application Security / DevSecOps engineer focused on secure SDLC, API and AI security, and CI/CD security automation. Based in Nairobi, open to relocation within the EU.
Certifications: CASP, CDP, CTMP, CCNSE, CCSE, CSSE, CSSA.
[LinkedIn](https://www.linkedin.com/in/beatrice-warukira) · [AI & API Security portfolio](https://github.com/Secsiren/ai-security-portfolio)

## Scope & ethics

Every project is an independent lab. All targets, data and captures are mock/synthetic and generated locally; no real system, network or personal data was involved. The OT project is passive (read-only) by design.
