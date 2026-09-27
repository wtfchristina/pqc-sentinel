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
