from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from scanner import audit_host

app = FastAPI(title="PQC Sentinel API")

class ScanRequest(BaseModel):
    domain: str

@app.post("/api/scan")
def scan_domain(request: ScanRequest):
    result = audit_host(request.domain)
    return result

app.mount("/", StaticFiles(directory="static", html=True), name="static")
