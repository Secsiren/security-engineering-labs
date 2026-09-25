"""OWASP API Security Top 10 (2023) attack tests.

Each attack is run against the vulnerable baseline (to prove it is real) and
against the secure API (to prove the control works). Test names carry the
threat-model ID from docs/threat-model.md.
"""
import sys
import time
from pathlib import Path

import jwt
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from api import secure_app, vulnerable_app  # noqa: E402

secure = TestClient(secure_app.app)
vuln = TestClient(vulnerable_app.app)


def token(sub="alice", **overrides):
    now = int(time.time())
    claims = {"sub": sub, "iat": now, "exp": now + 300,
              "aud": secure_app.JWT_AUDIENCE, "iss": secure_app.JWT_ISSUER}
    claims.update(overrides)
    return jwt.encode(claims, secure_app.JWT_SECRET, algorithm="HS256")


def hdr(tok):
    return {"Authorization": f"Bearer {tok}"}


def unsigned(sub):
    # alg=none token: header + payload, empty signature
    return jwt.encode({"sub": sub}, key=None, algorithm="none")


@pytest.fixture(autouse=True)
def reset_state():
    secure_app._hits.clear()
    for o in secure_app.ORDERS.values():
        o["note"] = ""
    yield


# --- T1 / API2 Broken authentication -----------------------------------------
def test_T1_unsigned_token_works_on_vulnerable_api():
    assert vuln.get("/users/me", headers=hdr(unsigned("bob"))).status_code == 200


def test_T1_unsigned_token_rejected():
    assert secure.get("/users/me", headers=hdr(unsigned("bob"))).status_code == 401


@pytest.mark.parametrize("bad", [
    {"exp": int(time.time()) - 600},          # expired
    {"aud": "billing-api"},                    # minted for a different API
    {"iss": "https://evil.example"},           # wrong issuer
])
def test_T2_invalid_claims_rejected(bad):
    assert secure.get("/users/me", headers=hdr(token(**bad))).status_code == 401


def test_T2_wrong_signing_key_rejected():
    forged = jwt.encode({"sub": "ops", "aud": "orders-api", "iss": secure_app.JWT_ISSUER,
                         "iat": int(time.time()), "exp": int(time.time()) + 60},
                        "attacker-guessed-key-that-is-long-enough", algorithm="HS256")
    assert secure.get("/users/me", headers=hdr(forged)).status_code == 401


def test_T2_missing_token_rejected():
    assert secure.get("/orders").status_code == 401


# --- T3 / API1 Broken object level authorization (BOLA) ---------------------
def test_T3_bola_works_on_vulnerable_api():
    r = vuln.get("/orders/102", headers=hdr(unsigned("alice")))
    assert r.status_code == 200 and r.json()["owner"] == "bob"


def test_T3_bola_blocked_and_does_not_confirm_existence():
    r = secure.get("/orders/102", headers=hdr(token("alice")))
    assert r.status_code == 404
    assert secure.get("/orders/999", headers=hdr(token("alice"))).status_code == 404


def test_T3_owner_can_read_own_order():
    assert secure.get("/orders/101", headers=hdr(token("alice"))).json()["item"] == "router"


# --- T4 / API3 Excessive data exposure --------------------------------------
def test_T4_password_hash_leaks_on_vulnerable_api():
    assert "password_hash" in vuln.get("/users/me", headers=hdr(unsigned("alice"))).json()


def test_T4_response_model_strips_sensitive_fields():
    body = secure.get("/users/me", headers=hdr(token("alice"))).json()
    assert set(body) == {"id", "email", "role"}


# --- T5 / API3 Mass assignment ----------------------------------------------
def test_T5_mass_assignment_works_on_vulnerable_api():
    r = vuln.patch("/orders/101", json={"price": 0}, headers=hdr(unsigned("alice")))
    assert r.json()["price"] == 0


def test_T5_mass_assignment_rejected():
    r = secure.patch("/orders/101", json={"note": "gift", "price": 0}, headers=hdr(token("alice")))
    assert r.status_code == 422
    assert secure_app.ORDERS[101]["price"] == 120


def test_T5_allowed_field_update_works():
    r = secure.patch("/orders/101", json={"note": "gift"}, headers=hdr(token("alice")))
    assert r.status_code == 200 and r.json()["note"] == "gift"


# --- T6 / API5 Broken function level authorization --------------------------
def test_T6_customer_cannot_call_admin_function():
    assert secure.delete("/admin/orders/102", headers=hdr(token("alice"))).status_code == 403


def test_T6_admin_can_call_admin_function():
    secure_app.ORDERS.setdefault(103, {"id": 103, "owner": "bob", "item": "x", "price": 1, "status": "paid", "note": ""})
    assert secure.delete("/admin/orders/103", headers=hdr(token("ops"))).status_code == 204


# --- T8 / API4 Unrestricted resource consumption ----------------------------
def test_T8_page_size_capped():
    assert secure.get("/orders?limit=100000", headers=hdr(token("alice"))).status_code == 422


def test_T8_rate_limit_per_subject():
    t = hdr(token("bob"))
    codes = [secure.get("/orders", headers=t).status_code for _ in range(25)]
    assert codes[:20] == [200] * 20 and 429 in codes[20:]
