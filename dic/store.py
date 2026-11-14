
import json
import sqlite3
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
DB_PATH = DATA_DIR / "dic.sqlite3"


def get_connection():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row

    return connection


def initialize_store():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                incident_type TEXT NOT NULL,
                severity INTEGER NOT NULL,
                detected_at INTEGER NOT NULL,
                incident_vector TEXT NOT NULL,
                vector_commitment TEXT,
                transaction_hash TEXT,
                block_number INTEGER,
                status TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS execution_actions (
                action_id INTEGER PRIMARY KEY,
                domain TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                action TEXT NOT NULL,
                status TEXT NOT NULL,
                receipt TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)


def save_incident(data: dict):
    with get_connection() as connection:
        connection.execute("""
            INSERT INTO incidents (
                incident_id,
                domain,
                incident_type,
                severity,
                detected_at,
                incident_vector,
                vector_commitment,
                transaction_hash,
                block_number,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(incident_id) DO UPDATE SET
                vector_commitment = excluded.vector_commitment,
                transaction_hash = excluded.transaction_hash,
                block_number = excluded.block_number,
                status = excluded.status
        """, (
            data["incident_id"],
            data["domain"],
            data["incident_type"],
            data["severity"],
            data["detected_at"],
            json.dumps(data["incident_vector"], sort_keys=True),
            data.get("vector_commitment"),
            data.get("transaction_hash"),
            data.get("block_number"),
            data["status"]
        ))


def get_incident(incident_id: str):
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM incidents WHERE incident_id = ?",
            (incident_id,)
        ).fetchone()

    if row is None:
        return None

    result = dict(row)
    result["incident_vector"] = json.loads(
        result["incident_vector"]
    )

    return result

def save_execution_action(
    action_id: int,
    domain: str,
    resource_id: str,
    action: str,
    status: str,
    receipt: dict | None = None
):
    with get_connection() as connection:
        connection.execute("""
            INSERT INTO execution_actions (
                action_id, domain, resource_id, action, status, receipt
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(action_id) DO UPDATE SET
                status = excluded.status,
                receipt = excluded.receipt,
                updated_at = CURRENT_TIMESTAMP
        """, (
            action_id,
            domain.upper(),
            resource_id,
            action.upper(),
            status.upper(),
            json.dumps(receipt, sort_keys=True) if receipt is not None else None
        ))


def get_execution_action_record(action_id: int):
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM execution_actions WHERE action_id = ?",
            (action_id,)
        ).fetchone()

    if row is None:
        return None

    result = dict(row)
    if result["receipt"]:
        result["receipt"] = json.loads(result["receipt"])

    return result