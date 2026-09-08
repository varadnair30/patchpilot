import jwt
from fastapi.testclient import TestClient

from app.auth import ISSUER, SECRET
from app.main import app

client = TestClient(app)


def _token() -> str:
    return jwt.encode({"sub": "alice", "iss": ISSUER}, SECRET, algorithm="HS256")


def test_health():
    assert client.get("/health").json() == {"ok": True}


def test_upload_requires_token():
    r = client.post("/upload", files={"file": ("a.txt", b"hello")}, data={"title": "t"})
    assert r.status_code == 401


def test_upload_ok():
    r = client.post(
        "/upload",
        headers={"Authorization": f"Bearer {_token()}"},
        files={"file": ("a.txt", b"hello")},
        data={"title": "notes"},
    )
    assert r.status_code == 200
    assert r.json()["bytes"] == 5
