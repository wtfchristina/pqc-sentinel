from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from scanner import audit_host
import os

app = FastAPI(title="PQC Sentinel API")

# Serve the static UI on the root path
@app.get("/", response_class=HTMLResponse)
async def serve_index():
    with open(os.path.join("static", "index.html"), "r") as f:
        return f.read()

# Mount the static directory
app.mount("/static", StaticFiles(directory="static"), name="static")

class ScanRequest(BaseModel):
    domain: str

@app.post("/api/scan")
def scan_domain(request: ScanRequest):
    result = audit_host(request.domain)
    return result

@app.post("/api/export/cbom")
def export_cbom(request: ScanRequest):
    result = audit_host(request.domain)

    is_secure = result.get("status") == "SECURE"
    risk_posture = "Quantum-Resistant" if is_secure else "Vulnerable: Harvest Now, Decrypt Later"
    nist_status = "Supported" if is_secure else "Not Supported"
    security_level = "Post-Quantum" if is_secure else "Classical"

    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": result.get("timestamp"),
            "component": {
                "type": "server",
                "name": result.get("domain"),
                "port": result.get("port")
            }
        },
        "components": [
            {
                "type": "cryptographic-asset",
                "name": "TLS Key Exchange",
                "cryptoProperties": {
                    "protocolVersion": "TLS 1.3",
                    "keyAgreementGroup": result.get("group"),
                    "nistFips203Status": nist_status,
                    "securityLevel": security_level,
                    "riskPosture": risk_posture
                }
            }
        ]
    }
    return cbom
