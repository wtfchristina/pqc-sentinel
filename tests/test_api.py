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
    assert len(components) == 1

    crypto_asset = components[0]
    assert crypto_asset["type"] == "cryptographic-asset"
    assert crypto_asset["name"] == "TLS Key Exchange"

    crypto_props = crypto_asset["cryptoProperties"]
    assert crypto_props["protocolVersion"] == "TLS 1.3"
    assert "keyAgreementGroup" in crypto_props
    assert crypto_props["nistFips203Status"] in ["Supported", "Not Supported"]
    assert crypto_props["securityLevel"] in ["Post-Quantum", "Classical"]
    assert crypto_props["riskPosture"] in ["Quantum-Resistant", "Vulnerable: Harvest Now, Decrypt Later"]

def test_export_pdf_api():
    response = client.post("/api/export/pdf", json={"domain": "example.com"})
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.content.startswith(b"%PDF-")
