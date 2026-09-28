from fastapi import FastAPI, File, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import re
from pydantic import BaseModel
from scanner import audit_host, audit_hosts_concurrent
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

class BatchScanRequest(BaseModel):
    domains: list[str]

@app.post("/api/scan/batch")
async def scan_batch(request: BatchScanRequest):
    results = await audit_hosts_concurrent(request.domains)
    return results

@app.post("/api/scan/upload")
async def scan_upload(file: UploadFile = File(...)):
    content = await file.read()
    text = content.decode("utf-8")
    # Split by lines or commas

    raw_domains = re.split(r'[\n,]', text)
    domains = [d.strip() for d in raw_domains if d.strip()]
    results = await audit_hosts_concurrent(domains)
    return results

@app.post("/api/scan")
def scan_domain(request: ScanRequest):
    result = audit_host(request.domain)
    return result

import io
from fastapi.responses import Response

@app.post("/api/export/pdf")
def export_pdf(request: ScanRequest):
    result = audit_host(request.domain)

    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        from reportlab.lib.colors import green, red, black, white
        from reportlab.lib.units import inch
        import textwrap
    except ImportError:
        return Response(content="ReportLab is not installed.", status_code=500)

    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    # Title
    c.setFont("Helvetica-Bold", 18)
    c.drawString(1 * inch, height - 1 * inch, "PQC Sentinel Executive Summary")

    # 1. Target hostname, scan timestamp, and port.
    c.setFont("Helvetica", 12)
    c.drawString(1 * inch, height - 1.5 * inch, f"Target Hostname: {result.get('domain', 'N/A')}")
    c.drawString(1 * inch, height - 1.75 * inch, f"Port: {result.get('port', 443)}")
    c.drawString(1 * inch, height - 2 * inch, f"Scan Timestamp: {result.get('timestamp', 'N/A')}")

    # 2. Compliance status badge
    is_secure = result.get("status") == "SECURE"
    c.setFont("Helvetica-Bold", 14)
    c.drawString(1 * inch, height - 2.5 * inch, "Compliance Status:")

    if is_secure:
        c.setFillColor(green)
        c.rect(1 * inch, height - 3 * inch, 5.5 * inch, 0.4 * inch, fill=1)
        c.setFillColor(white)
        c.drawString(1.1 * inch, height - 2.75 * inch, "FIPS 203 Hybrid Post-Quantum Ready")
    else:
        c.setFillColor(red)
        c.rect(1 * inch, height - 3 * inch, 5.5 * inch, 0.4 * inch, fill=1)
        c.setFillColor(white)
        c.drawString(1.1 * inch, height - 2.75 * inch, "Non-Compliant / Harvest Now Decrypt Later Risk")

    c.setFillColor(black)

    # 3. Negotiated cipher suite and key exchange group details.
    c.setFont("Helvetica-Bold", 14)
    c.drawString(1 * inch, height - 3.5 * inch, "Technical Details:")
    c.setFont("Helvetica", 12)
    c.drawString(1 * inch, height - 3.75 * inch, f"Key Exchange Group: {result.get('group', 'N/A')}")
    c.drawString(1 * inch, height - 4.0 * inch, "Cipher Suite: TLS 1.3 (Derived)")

    # 4. Executive recommendation block advising on NIST SP 800-227 migration steps.
    c.setFont("Helvetica-Bold", 14)
    c.drawString(1 * inch, height - 4.5 * inch, "Executive Recommendation:")
    c.setFont("Helvetica", 12)

    text = "Based on NIST SP 800-227 guidelines, it is recommended to transition to quantum-resistant cryptography. For non-compliant systems, prioritize updating TLS configurations to support hybrid key exchanges (e.g., X25519MLKEM768) to mitigate 'Harvest Now, Decrypt Later' threats. Ensure all cryptographic assets are inventoried and a migration plan is established."
    lines = textwrap.wrap(text, width=80)

    y = height - 4.75 * inch
    for line in lines:
        c.drawString(1 * inch, y, line)
        y -= 0.25 * inch

    c.showPage()
    c.save()

    pdf_bytes = buffer.getvalue()

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=executive-summary-{request.domain}.pdf"}
    )

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
