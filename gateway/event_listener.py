import json
import sqlite3
import threading
import time
from pathlib import Path

from gateway.config import CHAIN_ID
from gateway.client import BlockchainClient


ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "data" / "events.sqlite3"


def _json_value(value):
    if isinstance(value, (bytes, bytearray)):
        return "0x" + bytes(value).hex()
    if isinstance(value, dict):
        return {str(k): _json_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(v) for v in value]
    if hasattr(value, "hex") and not isinstance(value, str):
        try:
            return value.hex()
        except Exception:
            pass
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


class BlockchainEventListener:
    def __init__(self, client, poll_interval=2, start_block=None):
        self.client = client
        self.w3 = client.w3
        self.poll_interval = poll_interval
        self.start_block = (
            start_block if start_block is not None
            else self.w3.eth.block_number + 1
        )

        self.callbacks = {}
        self.stop_event = threading.Event()
        self.thread = None
        self.last_error = None

        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_database()

    def _connect(self):
        connection = sqlite3.connect(DB_PATH, timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize_database(self):
        with self._connect() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS event_checkpoints (
                    chain_id INTEGER NOT NULL,
                    contract_name TEXT NOT NULL,
                    event_name TEXT NOT NULL,
                    last_block INTEGER NOT NULL,
                    PRIMARY KEY (chain_id, contract_name, event_name)
                )
            """)

            db.execute("""
                CREATE TABLE IF NOT EXISTS blockchain_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chain_id INTEGER NOT NULL,
                    contract_name TEXT NOT NULL,
                    event_name TEXT NOT NULL,
                    transaction_hash TEXT NOT NULL,
                    log_index INTEGER NOT NULL,
                    block_number INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    dispatched INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
                    UNIQUE (chain_id, transaction_hash, log_index)
                )
            """)

    def subscribe(self, contract_name, event_name, callback):
        if contract_name not in self.client.contracts:
            raise ValueError(f"Unknown contract: {contract_name}")

        contract = self.client.get_contract(contract_name)
        available_events = {
            item["name"]
            for item in contract.abi
            if item.get("type") == "event"
        }

        if event_name not in available_events:
            raise ValueError(
                f"Event {event_name} not found in {contract_name}"
            )

        key = (contract_name, event_name)
        self.callbacks.setdefault(key, []).append(callback)

    def _get_checkpoint(self, db, contract_name, event_name):
        row = db.execute("""
            SELECT last_block
            FROM event_checkpoints
            WHERE chain_id = ? AND contract_name = ? AND event_name = ?
        """, (CHAIN_ID, contract_name, event_name)).fetchone()

        return row["last_block"] if row else self.start_block - 1

    def _save_checkpoint(self, db, contract_name, event_name, block_number):
        db.execute("""
            INSERT INTO event_checkpoints
                (chain_id, contract_name, event_name, last_block)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(chain_id, contract_name, event_name)
            DO UPDATE SET last_block = excluded.last_block
        """, (CHAIN_ID, contract_name, event_name, block_number))

    def _scan_event(self, contract_name, event_name, latest_block):
        contract = self.client.get_contract(contract_name)

        with self._connect() as db:
            last_block = self._get_checkpoint(
                db, contract_name, event_name
            )

            from_block = last_block + 1
            if from_block > latest_block:
                return

            event_factory = getattr(contract.events, event_name)
            event_logs = event_factory().get_logs(
                from_block=from_block,
                to_block=latest_block
            )

            for log in event_logs:
                transaction_hash = log["transactionHash"].hex()
                log_index = int(log["logIndex"])
                block_number = int(log["blockNumber"])

                payload = {
                    "contract": contract_name,
                    "event": event_name,
                    "address": log["address"],
                    "transaction_hash": transaction_hash,
                    "log_index": log_index,
                    "block_number": block_number,
                    "args": _json_value(dict(log["args"]))
                }

                db.execute("""
                    INSERT OR IGNORE INTO blockchain_events (
                        chain_id, contract_name, event_name,
                        transaction_hash, log_index, block_number, payload
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    CHAIN_ID,
                    contract_name,
                    event_name,
                    transaction_hash,
                    log_index,
                    block_number,
                    json.dumps(payload, separators=(",", ":"))
                ))

            self._save_checkpoint(
                db, contract_name, event_name, latest_block
            )

    def dispatch_pending(self):
        dispatched_count = 0

        with self._connect() as db:
            pending = db.execute("""
                SELECT id, contract_name, event_name, payload
                FROM blockchain_events
                WHERE dispatched = 0
                ORDER BY block_number, log_index
            """).fetchall()

        for row in pending:
            key = (row["contract_name"], row["event_name"])
            callbacks = self.callbacks.get(key, [])

            if not callbacks:
                continue

            payload = json.loads(row["payload"])

            try:
                for callback in callbacks:
                    callback(payload)

                with self._connect() as db:
                    db.execute("""
                        UPDATE blockchain_events
                        SET dispatched = 1
                        WHERE id = ?
                    """, (row["id"],))

                dispatched_count += 1

            except Exception as exc:
                self.last_error = (
                    f"Callback failed for {key}: {exc}"
                )

        return dispatched_count

    def poll_once(self):
        latest_block = self.w3.eth.block_number

        for contract_name, contract in self.client.contracts.items():
            for item in contract.abi:
                if item.get("type") != "event":
                    continue

                self._scan_event(
                    contract_name,
                    item["name"],
                    latest_block
                )

        return self.dispatch_pending()

    def _run(self):
        while not self.stop_event.is_set():
            try:
                self.poll_once()
                self.last_error = None
            except Exception as exc:
                self.last_error = str(exc)

            self.stop_event.wait(self.poll_interval)

    def start(self):
        if self.thread and self.thread.is_alive():
            return

        self.stop_event.clear()
        self.thread = threading.Thread(
            target=self._run,
            name="bficf-blockchain-events",
            daemon=True
        )
        self.thread.start()

    def stop(self):
        self.stop_event.set()

        if self.thread:
            self.thread.join(timeout=self.poll_interval + 5)

    def get_status(self):
        with self._connect() as db:
            total = db.execute(
                "SELECT COUNT(*) AS count FROM blockchain_events"
            ).fetchone()["count"]

            pending = db.execute(
                "SELECT COUNT(*) AS count FROM blockchain_events "
                "WHERE dispatched = 0"
            ).fetchone()["count"]

        return {
            "running": bool(self.thread and self.thread.is_alive()),
            "latest_block": self.w3.eth.block_number,
            "stored_events": total,
            "pending_events": pending,
            "last_error": self.last_error
        }
