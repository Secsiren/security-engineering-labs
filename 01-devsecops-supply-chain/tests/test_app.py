import sys
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.main import app  # noqa: E402

client = TestClient(app)


def test_health():
    assert client.get("/health").json() == {"status": "ok"}


def test_unknown_fields_rejected():
    r = client.post("/items", json={"name": "valve", "qty": 1, "is_admin": True})
    assert r.status_code == 422


def test_injection_characters_rejected():
    assert client.post("/items", json={"name": "x'; DROP TABLE items;--", "qty": 1}).status_code == 422


def test_bounds_enforced():
    assert client.post("/items", json={"name": "valve", "qty": -1}).status_code == 422


def test_docs_disabled_in_service():
    assert client.get("/docs").status_code == 404
