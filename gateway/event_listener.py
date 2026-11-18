import json
import threading

from eth_utils import event_abi_to_log_topic
from web3 import Web3

from gateway.config import CHAIN_ID, DATA_DIR
from gateway.db import connect


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

    def __init__(self, client, poll_interval=2, start_block="deployment", db_path=None,
                 max_block_range=2000, confirmations=0, max_attempts=5):
        self.client = client
        self.w3 = client.w3
        self.poll_interval = poll_interval
        self.confirmations = confirmations
        self.max_attempts = max_attempts
        self._range = max(1, int(max_block_range))

        self.db_path = db_path or (DATA_DIR / f"events_{client.domain.lower()}.sqlite3")
        if not hasattr(self.db_path, "parent"):
            from pathlib import Path
            self.db_path = Path(self.db_path)

        if start_block == "deployment":
            self.start_block = client.deployment_block
        elif start_block == "latest" or start_block is None:
            self.start_block = self.w3.eth.block_number + 1
        else:
            self.start_block = int(start_block)

        self._addresses = {c.address.lower(): name for name, c in client.contracts.items()}
        self._topics = {}
        for name, contract in client.contracts.items():
            for item in contract.abi:
                if item.get("type") == "event" and not item.get("anonymous"):
                    self._topics[(name, bytes(event_abi_to_log_topic(item)))] = item["name"]

        self.handlers = []            # {handler_id, contract, event, callback}
        self._handler_counts = {}
        self._poll_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.thread = None
        self.last_error = None

        self._initialize_database()



    def _initialize_database(self):
        with connect(self.db_path) as db:
            db.execute("""CREATE TABLE IF NOT EXISTS listener_state (
                chain_id INTEGER NOT NULL, key TEXT NOT NULL, value INTEGER NOT NULL,
                PRIMARY KEY (chain_id, key))""")
            db.execute("""CREATE TABLE IF NOT EXISTS blockchain_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chain_id INTEGER NOT NULL,
                contract_name TEXT NOT NULL,
                event_name TEXT NOT NULL,
                transaction_hash TEXT NOT NULL,
                log_index INTEGER NOT NULL,
                block_number INTEGER NOT NULL,
                block_timestamp INTEGER,
                payload TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                UNIQUE (chain_id, transaction_hash, log_index))""")
            db.execute("""CREATE TABLE IF NOT EXISTS handler_state (
                chain_id INTEGER NOT NULL, handler_id TEXT NOT NULL,
                last_event_id INTEGER NOT NULL DEFAULT 0,
                attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                PRIMARY KEY (chain_id, handler_id))""")
            db.execute("""CREATE TABLE IF NOT EXISTS dead_letters (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chain_id INTEGER NOT NULL, handler_id TEXT NOT NULL,
                event_id INTEGER NOT NULL, error TEXT,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')))""")

  

    def subscribe(self, contract_name, event_name, callback, handler_id=None, replay=True):
        if contract_name not in self.client.contracts:
            raise ValueError(f"Unknown contract: {contract_name}")

        available = {i["name"] for i in self.client.get_contract(contract_name).abi
                     if i.get("type") == "event"}
        if event_name not in available:
            raise ValueError(f"Event {event_name} not found in {contract_name}")
        if not callable(callback):
            raise TypeError("callback must be callable")

        base = handler_id or f"{getattr(callback, '__module__', '')}.{getattr(callback, '__qualname__', 'callback')}"
        full = f"{contract_name}.{event_name}:{base}"
        n = self._handler_counts.get(full, 0)
        self._handler_counts[full] = n + 1
        if n:
            full = f"{full}#{n}"

        self.handlers.append({"handler_id": full, "contract": contract_name,
                              "event": event_name, "callback": callback})

        with connect(self.db_path) as db:
            start = 0
            if not replay:
                start = db.execute("SELECT COALESCE(MAX(id), 0) AS m FROM blockchain_events").fetchone()["m"]
            db.execute("INSERT OR IGNORE INTO handler_state (chain_id, handler_id, last_event_id) VALUES (?, ?, ?)",
                       (CHAIN_ID, full, start))
        return full


    def _scan(self, latest_block):
        target = latest_block - self.confirmations
        addresses = [c.address for c in self.client.contracts.values()]

        with connect(self.db_path) as db:
            row = db.execute("SELECT value FROM listener_state WHERE chain_id = ? AND key = 'last_block'",
                             (CHAIN_ID,)).fetchone()
        from_block = (row["value"] + 1) if row else self.start_block

        while from_block <= target:
            to_block = min(from_block + self._range - 1, target)
            try:
                logs = self.w3.eth.get_logs({"address": addresses, "fromBlock": from_block, "toBlock": to_block})
            except Exception:
                if self._range == 1:
                    raise
                self._range = max(1, self._range // 2)
                continue

            decoded = self._decode(logs)

            with connect(self.db_path) as db:
                for item in decoded:
                    db.execute("""INSERT OR IGNORE INTO blockchain_events
                        (chain_id, contract_name, event_name, transaction_hash, log_index,
                         block_number, block_timestamp, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                        (CHAIN_ID, item["contract"], item["event"], item["transaction_hash"],
                         item["log_index"], item["block_number"], item["block_timestamp"],
                         json.dumps(item, separators=(",", ":"))))
                db.execute("""INSERT INTO listener_state (chain_id, key, value) VALUES (?, 'last_block', ?)
                    ON CONFLICT(chain_id, key) DO UPDATE SET value = excluded.value""", (CHAIN_ID, to_block))

            from_block = to_block + 1

    def _decode(self, logs):
        out, timestamps = [], {}
        for log in sorted(logs, key=lambda l: (l["blockNumber"], l["logIndex"])):
            contract_name = self._addresses.get(log["address"].lower())
            if contract_name is None or not log["topics"]:
                continue
            event_name = self._topics.get((contract_name, bytes(log["topics"][0])))
            if event_name is None:
                continue

            event = getattr(self.client.get_contract(contract_name).events, event_name)().process_log(log)
            block = int(log["blockNumber"])
            if block not in timestamps:
                timestamps[block] = int(self.w3.eth.get_block(block)["timestamp"])

            out.append({
                "contract": contract_name,
                "event": event_name,
                "address": log["address"],
                "transaction_hash": Web3.to_hex(log["transactionHash"]),
                "log_index": int(log["logIndex"]),
                "block_number": block,
                "block_timestamp": timestamps[block],
                "args": _json_value(dict(event["args"]))
            })
        return out



    def dispatch_pending(self):
        delivered = 0

        for handler in self.handlers:
            hid = handler["handler_id"]

            with connect(self.db_path) as db:
                state = db.execute("SELECT last_event_id, attempts FROM handler_state WHERE chain_id = ? AND handler_id = ?",
                                   (CHAIN_ID, hid)).fetchone()
                rows = db.execute("""SELECT id, payload FROM blockchain_events
                    WHERE id > ? AND contract_name = ? AND event_name = ? ORDER BY id LIMIT 1000""",
                    (state["last_event_id"], handler["contract"], handler["event"])).fetchall()
            attempts = state["attempts"]

            for row in rows:
                try:
                    handler["callback"](json.loads(row["payload"]))
                except Exception as exc:
                    attempts += 1
                    self.last_error = f"Handler {hid} failed on event {row['id']}: {exc}"
                    with connect(self.db_path) as db:
                        if attempts >= self.max_attempts:
                            db.execute("INSERT INTO dead_letters (chain_id, handler_id, event_id, error) VALUES (?, ?, ?, ?)",
                                       (CHAIN_ID, hid, row["id"], str(exc)))
                            db.execute("UPDATE handler_state SET last_event_id = ?, attempts = 0, last_error = ? WHERE chain_id = ? AND handler_id = ?",
                                       (row["id"], str(exc), CHAIN_ID, hid))
                            attempts = 0
                            continue                      # dead-lettered: move on to the next event
                        db.execute("UPDATE handler_state SET attempts = ?, last_error = ? WHERE chain_id = ? AND handler_id = ?",
                                   (attempts, str(exc), CHAIN_ID, hid))
                    break                                  # keep order: retry this event next poll

                attempts = 0
                delivered += 1
                with connect(self.db_path) as db:
                    db.execute("UPDATE handler_state SET last_event_id = ?, attempts = 0, last_error = NULL WHERE chain_id = ? AND handler_id = ?",
                               (row["id"], CHAIN_ID, hid))

        return delivered

    def poll_once(self):
        with self._poll_lock:
            self._scan(self.w3.eth.block_number)
            return self.dispatch_pending()


    def _run(self):
        while not self.stop_event.is_set():
            try:
                self.poll_once()
                if not self.last_error or not self.last_error.startswith("Handler"):
                    self.last_error = None
            except Exception as exc:
                self.last_error = str(exc)
            self.stop_event.wait(self.poll_interval)

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run, name=f"bficf-events-{self.client.domain}", daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=self.poll_interval + 5)



    def fetch_events(self, contract=None, event=None, since_id=0, limit=1000):
        query = "SELECT id, payload FROM blockchain_events WHERE id > ?"
        params = [since_id]
        if contract:
            query += " AND contract_name = ?"; params.append(contract)
        if event:
            query += " AND event_name = ?"; params.append(event)
        query += " ORDER BY id LIMIT ?"; params.append(limit)

        with connect(self.db_path) as db:
            return [{"id": r["id"], **json.loads(r["payload"])} for r in db.execute(query, params).fetchall()]

    def get_status(self):
        with connect(self.db_path) as db:
            total = db.execute("SELECT COUNT(*) AS c FROM blockchain_events").fetchone()["c"]
            dead = db.execute("SELECT COUNT(*) AS c FROM dead_letters").fetchone()["c"]
            last = db.execute("SELECT value FROM listener_state WHERE chain_id = ? AND key = 'last_block'",
                              (CHAIN_ID,)).fetchone()
            pending = 0
            for h in self.handlers:
                cursor = db.execute("SELECT last_event_id FROM handler_state WHERE chain_id = ? AND handler_id = ?",
                                    (CHAIN_ID, h["handler_id"])).fetchone()
                pending += db.execute(
                    "SELECT COUNT(*) AS c FROM blockchain_events WHERE id > ? AND contract_name = ? AND event_name = ?",
                    (cursor["last_event_id"] if cursor else 0, h["contract"], h["event"])).fetchone()["c"]

        return {
            "running": bool(self.thread and self.thread.is_alive()),
            "latest_block": self.w3.eth.block_number,
            "last_scanned_block": last["value"] if last else None,
            "stored_events": total,
            "pending_events": pending,        # undelivered (event, handler) pairs
            "dead_letters": dead,
            "last_error": self.last_error
        }
