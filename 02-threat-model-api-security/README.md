# 02 · Threat Model + API Security (OWASP API Top 10)

**Proves:** Certified Threat Modeling Professional (CTMP) and Certified API Security Professional (CASP) skills: turning a design into threats, threats into controls, and controls into tests.

**What's here**

| Path | Purpose |
|---|---|
| [`docs/threat-model.md`](docs/threat-model.md) | Data-flow diagram, trust boundaries, assets, STRIDE threats T1–T9 with risk ratings and residual risks |
| [`api/secure_app.py`](api/secure_app.py) | FastAPI Orders API; every control is tagged with its threat ID |
| [`api/vulnerable_app.py`](api/vulnerable_app.py) | Deliberately vulnerable baseline, used only to prove each attack is real |
| [`tests/test_api_security.py`](tests/test_api_security.py) | Attack tests: each runs against the vulnerable API (attack succeeds) and the secure API (attack blocked) |

## Coverage

| OWASP API Security Top 10 (2023) | Attack reproduced | Control |
|---|---|---|
| API1 Broken Object Level Authorization | Alice reads Bob's order by changing the ID | Owner check; 404 hides whether the ID exists |
| API2 Broken Authentication | `alg=none` token, expired token, wrong audience/issuer, forged signature | Pinned algorithm; required and validated claims |
| API3 Broken Object Property Level Authorization | Response leaks `password_hash`; PATCH sets `price=0` | Response models; write model with `extra="forbid"` |
| API4 Unrestricted Resource Consumption | `?limit=100000`; request flood | Page-size cap; per-subject rate limit (429) |
| API5 Broken Function Level Authorization | Customer calls `/admin/orders/{id}` | Role check on admin routes |
| API8 Security Misconfiguration | Stack traces, public docs UI | Generic error handler; docs disabled |

## Run

```bash
pip install -r ../requirements.txt
pytest -q        # 19 passed
```

*Lab project with mock users and data. No real system or personal data was tested.*
