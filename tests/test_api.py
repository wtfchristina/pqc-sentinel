from fastapi.testclient import TestClient
from app import app

client = TestClient(app)

def test_scan_api():
    response = client.post("/api/scan", json={"domain": "example.com"})
    assert response.status_code == 200

    data = response.json()
    assert data["domain"] == "example.com"
    assert "status" in data
    assert "group" in data
    assert "posture" in data
    assert "timestamp" in data
