"""Orders API built from the threat model in docs/threat-model.md.

Every control below is tagged with the threat ID (T1..T9) it mitigates and the
OWASP API Security Top 10 (2023) category, so reviewers can trace design ->
code -> test.
"""
from __future__ import annotations

import os
import secrets
import time
from collections import defaultdict, deque

import jwt
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

# No hard-coded fallback secret: if none is configured, a random one is generated,
# so a missing config can never produce a guessable signing key.
JWT_SECRET = os.environ.get("ORDERS_JWT_SECRET") or secrets.token_urlsafe(48)
JWT_ISSUER = "https://auth.example.test"
JWT_AUDIENCE = "orders-api"
MAX_PAGE_SIZE = 50
RATE_LIMIT = (20, 10.0)  # 20 requests per 10 seconds per subject

app = FastAPI(title="orders-api", docs_url=None, redoc_url=None)

MOCK_PW_HASH = "stored-in-idp-not-here"  # nosec B105 - lab placeholder, no real secret

USERS = {
    "alice": {"id": "alice", "email": "alice@example.test", "password_hash": MOCK_PW_HASH, "role": "customer"},
    "bob": {"id": "bob", "email": "bob@example.test", "password_hash": MOCK_PW_HASH, "role": "customer"},
    "ops": {"id": "ops", "email": "ops@example.test", "password_hash": MOCK_PW_HASH, "role": "admin"},
}
ORDERS = {
    101: {"id": 101, "owner": "alice", "item": "router", "price": 120, "status": "paid", "note": ""},
    102: {"id": 102, "owner": "bob", "item": "switch", "price": 80, "status": "paid", "note": ""},
}
_hits: dict[str, deque] = defaultdict(deque)


# --- T1/T2 Spoofing: strict token validation (API2 Broken Authentication) ----
def current_user(request: Request) -> dict:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer token")
    token = auth.split(" ", 1)[1]
    try:
        claims = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"],          # pinned: rejects alg=none and algorithm confusion
            audience=JWT_AUDIENCE,          # token minted for another API is rejected
            issuer=JWT_ISSUER,
            options={"require": ["exp", "iat", "sub", "aud", "iss"]},
            leeway=5,
        )
    except jwt.PyJWTError:
        raise HTTPException(401, "invalid token")  # generic: no oracle for attackers
    user = USERS.get(claims["sub"])
    if user is None:
        raise HTTPException(401, "invalid token")
    _rate_limit(user["id"])
    return user


# --- T8 Denial of service: per-subject rate limit (API4) ---------------------
def _rate_limit(subject: str) -> None:
    limit, window = RATE_LIMIT
    now = time.monotonic()
    q = _hits[subject]
    while q and now - q[0] > window:
        q.popleft()
    if len(q) >= limit:
        raise HTTPException(429, "rate limit exceeded")
    q.append(now)


def require_admin(user: dict = Depends(current_user)) -> dict:
    # --- T6 Elevation of privilege: function-level authorization (API5) -----
    if user["role"] != "admin":
        raise HTTPException(403, "forbidden")
    return user


# --- T4 Information disclosure: explicit response models (API3) -------------
class UserOut(BaseModel):
    id: str
    email: str
    role: str


class OrderOut(BaseModel):
    id: int
    item: str
    price: int
    status: str
    note: str


class OrderPatch(BaseModel):
    # T5 Tampering: only "note" is client-writable; price/status/owner are not (API3 mass assignment)
    model_config = ConfigDict(extra="forbid")
    note: str = Field(max_length=280)


def _owned_order(order_id: int, user: dict) -> dict:
    # --- T3 Tampering/Info disclosure: object-level authorization (API1 BOLA)
    order = ORDERS.get(order_id)
    if order is None or (order["owner"] != user["id"] and user["role"] != "admin"):
        raise HTTPException(404, "not found")  # 404, not 403: don't confirm the ID exists
    return order


@app.get("/users/me", response_model=UserOut)
def me(user: dict = Depends(current_user)):
    return user


@app.get("/orders", response_model=list[OrderOut])
def list_orders(limit: int = Query(20, ge=1, le=MAX_PAGE_SIZE), user: dict = Depends(current_user)):
    mine = [o for o in ORDERS.values() if o["owner"] == user["id"]]
    return mine[:limit]


@app.get("/orders/{order_id}", response_model=OrderOut)
def get_order(order_id: int, user: dict = Depends(current_user)):
    return _owned_order(order_id, user)


@app.patch("/orders/{order_id}", response_model=OrderOut)
def patch_order(order_id: int, body: OrderPatch, user: dict = Depends(current_user)):
    order = _owned_order(order_id, user)
    order["note"] = body.note
    return order


@app.delete("/admin/orders/{order_id}", status_code=204)
def admin_delete(order_id: int, admin: dict = Depends(require_admin)):
    ORDERS.pop(order_id, None)


# --- T7 Information disclosure: no stack traces to clients (API8) -----------
@app.exception_handler(Exception)
async def unhandled(_: Request, __: Exception):
    return JSONResponse(status_code=500, content={"detail": "internal error"})
