# PQC Sentinel

[![CI](https://github.com/wtfchristina/pqc-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/wtfchristina/pqc-sentinel/actions)
![Release](https://img.shields.io/github/v/release/wtfchristina/pqc-sentinel)
![NIST](https://img.shields.io/badge/NIST-FIPS%20203%20ML--KEM-blue)

**PQC Sentinel** is a domain-level audit platform and API designed to detect Post-Quantum Cryptography (PQC) readiness. It performs TLS 1.3 ClientHello negotiations with hybrid post-quantum key encapsulation mechanisms (ML-KEM-768 / X25519) to detect compliance with **NIST FIPS 203** and mitigate "Harvest Now, Decrypt Later" (HNDL) exposure.

## Features

- **TLS 1.3 PQC Engine**: Evaluates whether remote hosts negotiate hybrid post-quantum groups (`X25519MLKEM768`).
- **Interactive UI**: Real-time status cards (SECURE vs. VULNERABLE).
- **CycloneDX CBOM Export**: Exports machine-readable Cryptographic Bill of Materials (CBOM) in JSON format.
- **Executive Audit PDF**: Generates downloadable 1-page compliance summaries via ReportLab.
- **Container Ready**: Built for cloud deployment via a lightweight multi-stage Docker container.

## Local Quickstart

```bash
# Clone and enter repo
git clone [https://github.com/wtfchristina/pqc-sentinel.git](https://github.com/wtfchristina/pqc-sentinel.git)
cd pqc-sentinel

# Setup environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run server
python -m uvicorn app:app --reload
python -m pytest
