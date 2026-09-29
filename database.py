import sqlite3
import os

def get_db():
    db_path = os.environ.get("PQC_SENTINEL_DB_PATH", "pqc_sentinel.db")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    # Table for monitored domains
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS monitored_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            port INTEGER DEFAULT 443,
            last_status TEXT,
            last_group TEXT,
            last_signature_algorithm TEXT,
            webhook_url TEXT,
            is_active INTEGER DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_scanned_at DATETIME
        )
    ''')

    # Table for audit history
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_id INTEGER NOT NULL,
            status TEXT,
            "group" TEXT,
            leaf_signature_algorithm TEXT,
            signature_pqc_status TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(domain_id) REFERENCES monitored_domains(id) ON DELETE CASCADE
        )
    ''')

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    db_path = os.environ.get("PQC_SENTINEL_DB_PATH", "pqc_sentinel.db")
    print(f"Database initialized at {db_path}")
