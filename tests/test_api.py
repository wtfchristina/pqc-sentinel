from fastapi.testclient import TestClient
from app import app

client = TestClient(app)

def test_serve_index():
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "PQC Sentinel" in response.text

def test_scan_api():
    response = client.post("/api/scan", json={"domain": "example.com"})
    assert response.status_code == 200

    data = response.json()
    assert data["domain"] == "example.com"
    assert "status" in data
    assert "group" in data
    assert "posture" in data
    assert "timestamp" in data
    assert "leaf_signature_algorithm" in data
    assert "leaf_key_type" in data
    assert "leaf_key_size_bits" in data
    assert "signature_pqc_status" in data

def test_export_cbom_api():
    response = client.post("/api/export/cbom", json={"domain": "example.com"})
    assert response.status_code == 200

    cbom = response.json()

    # Check general structure
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.5"
    assert "metadata" in cbom
    assert "components" in cbom

    # Check metadata
    assert cbom["metadata"]["component"]["type"] == "server"
    assert cbom["metadata"]["component"]["name"] == "example.com"

    # Check components
    components = cbom["components"]
    assert len(components) == 2

    crypto_asset = components[0]
    assert crypto_asset["type"] == "cryptographic-asset"
    assert crypto_asset["name"] == "TLS Key Exchange"

    crypto_props = crypto_asset["cryptoProperties"]
    assert crypto_props["protocolVersion"] == "TLS 1.3"
    assert "keyAgreementGroup" in crypto_props
    assert crypto_props["nistFips203Status"] in ["Supported", "Not Supported"]
    assert crypto_props["securityLevel"] in ["Post-Quantum", "Classical"]
    assert crypto_props["riskPosture"] in ["Quantum-Resistant", "Vulnerable: Harvest Now, Decrypt Later"]

    sig_asset = components[1]
    assert sig_asset["type"] == "cryptographic-asset"
    assert sig_asset["name"] == "Certificate Signature Algorithm"

    sig_props = sig_asset["cryptoProperties"]
    assert "algorithm" in sig_props
    assert "nistFips204_205Status" in sig_props

def test_export_pdf_api():
    response = client.post("/api/export/pdf", json={"domain": "example.com"})
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.content.startswith(b"%PDF-")

def test_scan_batch_api():
    response = client.post("/api/scan/batch", json={"domains": ["example.com", "test.com"]})
    assert response.status_code == 200

    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 2

    # Check structure of the first item
    item = data[0]
    assert item["domain"] == "example.com"
    assert "status" in item
    assert "group" in item
    assert "posture" in item
    assert "timestamp" in item
    assert "leaf_signature_algorithm" in item
    assert "leaf_key_type" in item
    assert "leaf_key_size_bits" in item
    assert "signature_pqc_status" in item

    # Check structure of the second item
    item2 = data[1]
    assert item2["domain"] == "test.com"
    assert "status" in item2
    assert "group" in item2
    assert "posture" in item2
    assert "timestamp" in item2
    assert "leaf_signature_algorithm" in item2
    assert "leaf_key_type" in item2
    assert "leaf_key_size_bits" in item2
    assert "signature_pqc_status" in item2

import os
from database import init_db, get_db

# Initialize a test DB
os.environ["PQC_SENTINEL_DB_PATH"] = "pqc_sentinel_test.db"
if os.path.exists("pqc_sentinel_test.db"):
    os.remove("pqc_sentinel_test.db")
init_db()

def test_add_target():
    response = client.post("/api/monitor/targets", json={"domain": "example.com", "webhook_url": "http://test.webhook"})
    assert response.status_code == 200
    data = response.json()
    assert "id" in data
    assert data["message"] == "Domain added to monitoring"

def test_list_targets():
    response = client.get("/api/monitor/targets")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    # Check that "example.com" is in the results
    assert any(t["domain"] == "example.com" for t in data)

def test_delete_target():
    # First, get the id
    response = client.get("/api/monitor/targets")
    data = response.json()
    target_id = data[0]["id"]

    # Delete it
    response = client.delete(f"/api/monitor/targets/{target_id}")
    assert response.status_code == 200
    assert response.json()["message"] == "Domain removed from monitoring"

    # Verify it's gone
    response = client.get("/api/monitor/targets")
    data = response.json()
    # It should not contain the deleted target
    assert not any(t["id"] == target_id for t in data)

from unittest.mock import patch

@patch("alerts.httpx.AsyncClient.post")
def test_run_check_with_drift(mock_post):
    # Setup test DB specifically for drift check
    conn = get_db()
    cursor = conn.cursor()
    # Add a target that was SECURE and has a PQC sig
    cursor.execute("""
        INSERT INTO monitored_domains (domain, webhook_url, is_active, last_status, last_signature_algorithm)
        VALUES (?, ?, 1, ?, ?)
    """, ("test-drift.com", "http://test.webhook", "SECURE", "mldsa44"))
    conn.commit()
    conn.close()

    # We mock the actual scanner to simulate a regression
    with patch("app.audit_hosts_concurrent") as mock_audit:
        import asyncio
        # Provide results matching the number of active targets
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT count(*) FROM monitored_domains WHERE is_active = 1")
        count = cursor.fetchone()[0]
        conn.close()

        # Simulate result where it regressed to VULNERABLE and classical sig for all
        mock_audit.return_value = [{"status": "VULNERABLE", "group": "Legacy", "leaf_signature_algorithm": "ecdsa-with-SHA256", "signature_pqc_status": "Classical"} for _ in range(count)]

        # To avoid the coroutine warning from the mock, we can mock raise_for_status
        from unittest.mock import AsyncMock
        mock_post.return_value = AsyncMock()
        mock_post.return_value.raise_for_status = lambda: None

        response = client.post("/api/monitor/run-check")
        assert response.status_code == 200

        # Verify the webhook was called because of drift
        assert mock_post.call_count >= 1

        # We find the specific call for our drift target
        drift_call = None
        for call in mock_post.mock_calls:
            if call.kwargs and "json" in call.kwargs:
                if call.kwargs["json"].get("domain") == "test-drift.com":
                    drift_call = call
                    break

        assert drift_call is not None
        payload = drift_call.kwargs["json"]
        assert "Status regressed from SECURE to VULNERABLE." in payload["reasons"]
