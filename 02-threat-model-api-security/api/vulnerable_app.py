"""Deliberately vulnerable baseline, kept ONLY so the tests can prove each
attack works before the fix. Never deploy this file.

Flaws: accepts unsigned tokens (alg=none), no object-level authorization
(BOLA), mass assignment on PATCH, no page-size cap, and returns the full
user record including the password hash.
"""
from __future__ import annotations

import jwt
from fastapi import FastAPI, Request

app = FastAPI(title="orders-api-vulnerable")

MOCK_PW_HASH = "stored-in-idp-not-here"  # nosec B105 - lab placeholder, no real secret

USERS = {
    "alice": {"id": "alice", "email": "alice@example.test", "password_hash": MOCK_PW_HASH, "role": "customer"},
    "bob": {"id": "bob", "email": "bob@example.test", "password_hash": MOCK_PW_HASH, "role": "customer"},
}
ORDERS = {
    101: {"id": 101, "owner": "alice", "item": "router", "price": 120, "status": "paid", "note": ""},
    102: {"id": 102, "owner": "bob", "item": "switch", "price": 80, "status": "paid", "note": ""},
}


def _user(request: Request) -> dict:
    token = request.headers.get("authorization", "").split(" ", 1)[-1]
    claims = jwt.decode(token, options={"verify_signature": False})  # FLAW: signature never checked
    return USERS[claims["sub"]]


@app.get("/users/me")
def me(request: Request):
    return _user(request)  # FLAW: leaks password_hash


@app.get("/orders/{order_id}")
def get_order(order_id: int, request: Request):
    _user(request)
    return ORDERS[order_id]  # FLAW: any user can read any order (BOLA)


@app.patch("/orders/{order_id}")
async def patch_order(order_id: int, request: Request):
    _user(request)
    ORDERS[order_id].update(await request.json())  # FLAW: mass assignment
    return ORDERS[order_id]
