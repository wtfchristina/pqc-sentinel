from fastapi import FastAPI, File, UploadFile, HTTPException, Depends
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import re
from pydantic import BaseModel
from typing import Optional
from scanner import audit_host, audit_hosts_concurrent
import os
from contextlib import asynccontextmanager
from database import init_db, get_db
from alerts import send_drift_alert
from scheduler import start_scheduler, stop_scheduler, get_scheduler_status

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    start_scheduler(_internal_run_monitor_check)
    yield
    stop_scheduler()

app = FastAPI(title="PQC Sentinel API", lifespan=lifespan)

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

class MonitorTarget(BaseModel):
    domain: str
    webhook_url: Optional[str] = None

@app.post("/api/monitor/targets")
def add_monitor_target(target: MonitorTarget):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO monitored_domains (domain, webhook_url) VALUES (?, ?)",
        (target.domain, target.webhook_url)
    )
    conn.commit()
    target_id = cursor.lastrowid
    conn.close()
    return {"id": target_id, "message": "Domain added to monitoring"}

@app.get("/api/monitor/targets")
def get_monitor_targets():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, domain, port, last_status, last_group, last_signature_algorithm,
               webhook_url, is_active, created_at, last_scanned_at
        FROM monitored_domains WHERE is_active = 1
    """)
    rows = cursor.fetchall()

    # Also fetch recent history for each
    targets = []
    for row in rows:
        target = dict(row)
        cursor.execute("""
            SELECT status, "group", leaf_signature_algorithm, signature_pqc_status, timestamp
            FROM audit_history
            WHERE domain_id = ?
            ORDER BY timestamp DESC LIMIT 5
        """, (target["id"],))
        target["history"] = [dict(h) for h in cursor.fetchall()]
        targets.append(target)

    conn.close()
    return targets

@app.delete("/api/monitor/targets/{target_id}")
def delete_monitor_target(target_id: int):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE monitored_domains SET is_active = 0 WHERE id = ?", (target_id,))
    conn.commit()
    conn.close()
    return {"message": "Domain removed from monitoring"}

async def _internal_run_monitor_check():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, domain, webhook_url, last_status, last_signature_algorithm FROM monitored_domains WHERE is_active = 1")
    targets = cursor.fetchall()

    if not targets:
        conn.close()
        return {"message": "No active targets to monitor."}

    domains = [t["domain"] for t in targets]
    results = await audit_hosts_concurrent(domains)

    alerts_triggered = 0

    for target, result in zip(targets, results):
        domain_id = target["id"]
        webhook_url = target["webhook_url"]
        prev_status = target["last_status"]
        prev_sig_alg = target["last_signature_algorithm"]

        curr_status = result.get("status")
        curr_group = result.get("group")
        curr_sig_alg = result.get("leaf_signature_algorithm")
        curr_sig_pqc = result.get("signature_pqc_status")

        # Insert history
        cursor.execute("""
            INSERT INTO audit_history (domain_id, status, "group", leaf_signature_algorithm, signature_pqc_status)
            VALUES (?, ?, ?, ?, ?)
        """, (domain_id, curr_status, curr_group, curr_sig_alg, curr_sig_pqc))

        # Update monitored domain
        cursor.execute("""
            UPDATE monitored_domains
            SET last_status = ?, last_group = ?, last_signature_algorithm = ?, last_scanned_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (curr_status, curr_group, curr_sig_alg, domain_id))

        # Check for drift
        drift_reasons = []
        if prev_status == "SECURE" and curr_status == "VULNERABLE":
            drift_reasons.append("Status regressed from SECURE to VULNERABLE.")

        if prev_sig_alg and prev_sig_alg != curr_sig_alg:
            # Simple heuristic for weakening: going from a PQC sig to classical
            if "mldsa" in prev_sig_alg.lower() and "mldsa" not in curr_sig_alg.lower():
                 drift_reasons.append(f"Signature algorithm weakened from {prev_sig_alg} to {curr_sig_alg}.")

        if drift_reasons and webhook_url:
            alert_payload = {
                "text": f"PQC Drift Alert for {target['domain']}",
                "domain": target['domain'],
                "reasons": drift_reasons,
                "previous_status": prev_status,
                "current_status": curr_status
            }
            await send_drift_alert(webhook_url, alert_payload)
            alerts_triggered += 1

    conn.commit()
    conn.close()

    return {"message": "Monitor check completed", "targets_checked": len(targets), "alerts_triggered": alerts_triggered}

@app.get("/api/monitor/scheduler-status")
def get_monitor_scheduler_status():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT count(*) FROM monitored_domains WHERE is_active = 1")
    count = cursor.fetchone()[0]
    conn.close()
    return get_scheduler_status(total_monitored_domains=count)

@app.post("/api/monitor/run-check")
async def run_monitor_check():
    return await _internal_run_monitor_check()

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
    c.drawString(1 * inch, height - 4.25 * inch, f"Certificate Signature Algorithm: {result.get('leaf_signature_algorithm', 'N/A')} ({result.get('signature_pqc_status', 'N/A')})")

    # 4. Executive recommendation block advising on NIST SP 800-227 migration steps.
    c.setFont("Helvetica-Bold", 14)
    c.drawString(1 * inch, height - 4.75 * inch, "Executive Recommendation:")
    c.setFont("Helvetica", 12)

    text = "Based on NIST SP 800-227 guidelines, it is recommended to transition to quantum-resistant cryptography. For non-compliant systems, prioritize updating TLS configurations to support hybrid key exchanges (e.g., X25519MLKEM768) to mitigate 'Harvest Now, Decrypt Later' threats. Ensure all cryptographic assets are inventoried and a migration plan is established."
    lines = textwrap.wrap(text, width=80)

    y = height - 5.0 * inch
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
            },
            {
                "type": "cryptographic-asset",
                "name": "Certificate Signature Algorithm",
                "cryptoProperties": {
                    "algorithm": result.get("leaf_signature_algorithm", "Unknown"),
                    "nistFips204_205Status": result.get("signature_pqc_status", "Unknown")
                }
            }
        ]
    }
    return cbom
