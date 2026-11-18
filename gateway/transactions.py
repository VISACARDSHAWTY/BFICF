import json
import threading
import time

from web3 import Web3
from web3.exceptions import TransactionNotFound, ContractLogicError

from gateway.config import DATA_DIR, GAS_PRICE, GAS_MARGIN, GAS_FALLBACK, GAS_LIMIT_CAP
from gateway.db import connect
from gateway.errors import GatewayRevert, TransactionReverted, TransactionTimeout

DB_PATH = DATA_DIR / "transactions.sqlite3"

_ALREADY_KNOWN = ("already known", "known transaction", "already imported", "already in the pool")

_init_lock = threading.Lock()
_initialized = set()


def _revert_reason(exc):
    text = getattr(exc, "message", None) or str(exc)
    for prefix in ("execution reverted: ", "execution reverted", "VM Exception while processing transaction: reverted with reason string "):
        if text.startswith(prefix):
            text = text[len(prefix):]
    return text.strip().strip("'\"") or "execution reverted"


def _looks_like_revert(exc):
    text = str(exc).lower()
    return isinstance(exc, ContractLogicError) or "revert" in text


class TransactionManager:

    _account_locks = {}
    _lock_guard = threading.Lock()

    def __init__(self, client, receipt_timeout=120, poll_interval=2, max_broadcast_attempts=4):
        self.client = client
        self.w3 = client.w3
        self.account = client.account
        self.receipt_timeout = receipt_timeout
        self.poll_interval = poll_interval
        self.max_broadcast_attempts = max_broadcast_attempts

        key = self.account.address.lower()
        with self._lock_guard:
            if key not in self._account_locks:
                self._account_locks[key] = threading.Lock()
        self._nonce_lock = self._account_locks[key]

        with _init_lock:
            if str(DB_PATH) not in _initialized:
                self._initialize_database()
                _initialized.add(str(DB_PATH))



    def _initialize_database(self):
        with connect(DB_PATH) as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS transactions (
                    account TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    transaction_hash TEXT NOT NULL,
                    raw_transaction TEXT NOT NULL,
                    status TEXT NOT NULL,
                    block_number INTEGER,
                    gas_used INTEGER,
                    created_at INTEGER NOT NULL,
                    nonce INTEGER,
                    chain_id INTEGER,
                    PRIMARY KEY (account, idempotency_key)
                )
            """)

            existing = {r["name"] for r in db.execute("PRAGMA table_info(transactions)").fetchall()}
            for column, ddl in (
                ("nonce", "INTEGER"), ("chain_id", "INTEGER"),
                ("contract", "TEXT"), ("function", "TEXT"),
                ("gas_limit", "INTEGER"),
                ("submitted_at", "REAL"), ("confirmed_at", "REAL"),
                ("block_timestamp", "INTEGER"), ("error", "TEXT"),
            ):
                if column not in existing:
                    db.execute(f"ALTER TABLE transactions ADD COLUMN {column} {ddl}")

            db.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_transactions_account_chain_nonce
                ON transactions(account, chain_id, nonce) WHERE nonce IS NOT NULL
            """)

            db.execute("""
                CREATE TABLE IF NOT EXISTS transaction_history (
                    account TEXT, idempotency_key TEXT, transaction_hash TEXT,
                    status TEXT, nonce INTEGER, chain_id INTEGER, block_number INTEGER,
                    error TEXT, archived_at INTEGER
                )
            """)

    def _update(self, transaction_hash, **fields):
        sets = ", ".join(f"{k} = ?" for k in fields)
        with connect(DB_PATH) as db:
            db.execute(f"UPDATE transactions SET {sets} WHERE transaction_hash = ?",
                       (*fields.values(), transaction_hash))



    def _calldata(self, contract_function):
        try:
            return contract_function._encode_transaction_data()
        except AttributeError:   # other web3 versions
            built = contract_function.build_transaction({
                "from": self.account.address, "gas": 1, "gasPrice": 0,
                "nonce": 0, "chainId": self.w3.eth.chain_id})
            return built["data"]

    def _request_hash(self, contract_function):
        payload = {
            "chain_id": self.w3.eth.chain_id,
            "sender": self.account.address.lower(),
            "contract": str(getattr(contract_function, "address", "")).lower(),
            "calldata": self._calldata(contract_function),
            "value": 0
        }
        return Web3.to_hex(Web3.keccak(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")))

    def _simulate(self, contract_function):
        name = getattr(contract_function, "fn_name", "call")
        sender = {"from": self.account.address}

        try:
            contract_function.call(sender)
        except Exception as exc:
            if _looks_like_revert(exc):
                raise GatewayRevert(_revert_reason(exc), function=name) from exc
            raise

        try:
            estimate = int(contract_function.estimate_gas(sender))
            gas = int(estimate * GAS_MARGIN) + 1000
        except Exception:
            gas = GAS_FALLBACK   

        return max(21000, min(gas, GAS_LIMIT_CAP))

    

    def _fetch(self, db, account, key):
        row = db.execute(
            "SELECT * FROM transactions WHERE account = ? AND idempotency_key = ?",
            (account, key)).fetchone()
        return dict(row) if row else None

    def _archive(self, db, row):
        db.execute("""
            INSERT INTO transaction_history
            (account, idempotency_key, transaction_hash, status, nonce, chain_id, block_number, error, archived_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (row["account"], row["idempotency_key"], row["transaction_hash"], row["status"],
              row["nonce"], row["chain_id"], row["block_number"], row.get("error"), int(time.time())))
        db.execute("DELETE FROM transactions WHERE account = ? AND idempotency_key = ?",
                   (row["account"], row["idempotency_key"]))

    def _load_or_create_transaction(self, contract_function, idempotency_key):
        request_hash = self._request_hash(contract_function)
        account = self.account.address.lower()
        chain_id = self.w3.eth.chain_id

        with connect(DB_PATH) as db:
            existing = self._fetch(db, account, idempotency_key)

        if existing:
            if existing["request_hash"] != request_hash:
                raise ValueError("This idempotency key was already used for a different transaction.")
            if existing["status"] != "REVERTED":
                return existing
           

        gas = self._simulate(contract_function)          

        with connect(DB_PATH) as db:
            db.execute("BEGIN IMMEDIATE")             

            existing = self._fetch(db, account, idempotency_key)
            if existing:
                if existing["status"] != "REVERTED":
                    return existing                      
                self._archive(db, existing)

            pending_nonce = self.w3.eth.get_transaction_count(self.account.address, "pending")
            last = db.execute(
                "SELECT MAX(nonce) AS n FROM transactions WHERE account = ? AND chain_id = ?",
                (account, chain_id)).fetchone()["n"]
            nonce = pending_nonce if last is None else max(pending_nonce, last + 1)

            transaction = contract_function.build_transaction({
                "from": self.account.address,
                "nonce": nonce,
                "chainId": chain_id,
                "gasPrice": GAS_PRICE,
                "gas": gas
            })
            signed = self.account.sign_transaction(transaction)
            tx_hash = Web3.to_hex(signed.hash)
            raw = Web3.to_hex(signed.raw_transaction)

            db.execute("""
                INSERT INTO transactions (
                    account, idempotency_key, request_hash, transaction_hash, raw_transaction,
                    status, created_at, nonce, chain_id, contract, function, gas_limit
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (account, idempotency_key, request_hash, tx_hash, raw, "PREPARED",
                  int(time.time()), nonce, chain_id,
                  str(getattr(contract_function, "address", "")).lower(),
                  getattr(contract_function, "fn_name", None), gas))

            return {
                "account": account, "idempotency_key": idempotency_key,
                "transaction_hash": tx_hash, "raw_transaction": raw,
                "status": "PREPARED", "nonce": nonce, "chain_id": chain_id,
                "block_number": None, "gas_used": None
            }



    def _broadcast(self, transaction):
        raw = bytes.fromhex(transaction["raw_transaction"].removeprefix("0x"))
        expected_hash = transaction["transaction_hash"]
        now = time.time()

        try:
            self.w3.eth.get_transaction_receipt(expected_hash)
            return Web3.to_bytes(hexstr=expected_hash)
        except TransactionNotFound:
            pass
        try:
            self.w3.eth.get_transaction(expected_hash)
            self._update(expected_hash, status="BROADCAST")
            return Web3.to_bytes(hexstr=expected_hash)
        except TransactionNotFound:
            pass

        for attempt in range(self.max_broadcast_attempts):
            try:
                tx_hash = self.w3.eth.send_raw_transaction(raw)
                self._update(expected_hash, status="BROADCAST", submitted_at=now)
                return tx_hash
            except Exception as exc:
                message = str(exc).lower()

                if any(m in message for m in _ALREADY_KNOWN):
                    self._update(expected_hash, status="BROADCAST")
                    return Web3.to_bytes(hexstr=expected_hash)

                if "nonce too low" in message:
                    try:
                        return self.w3.eth.get_transaction_receipt(expected_hash).transactionHash
                    except TransactionNotFound:
                        raise RuntimeError(
                            "The transaction nonce was consumed, but this transaction was not found. "
                            f"Hash: {expected_hash}") from exc

                if attempt == self.max_broadcast_attempts - 1:
                    raise RuntimeError(
                        "Transaction broadcast remains uncertain. Retry using the same "
                        f"idempotency key. Transaction hash: {expected_hash}. Error: {exc}") from exc

                time.sleep(2 ** attempt)

        raise RuntimeError("Transaction broadcast failed.")

    def _wait_for_receipt(self, tx_hash):
        deadline = time.monotonic() + self.receipt_timeout
        delay = self.poll_interval
        last_error = None

        while time.monotonic() < deadline:
            try:
                return self.w3.eth.get_transaction_receipt(tx_hash)
            except TransactionNotFound:
                time.sleep(delay)
            except Exception as exc:
                last_error = exc
                time.sleep(delay)
            delay = min(delay * 1.5, 10)

        message = f"Transaction was broadcast but no receipt was found. Hash: {Web3.to_hex(tx_hash)}"
        if last_error:
            message += f" Last RPC error: {last_error}"
        raise TransactionTimeout(message)

    def _finish(self, transaction):
        tx_hash = self._broadcast(transaction)
        receipt = self._wait_for_receipt(tx_hash)
        hash_hex = Web3.to_hex(tx_hash)

        if receipt.status != 1:
            self._update(transaction["transaction_hash"], status="REVERTED",
                         block_number=receipt.blockNumber, gas_used=receipt.gasUsed,
                         error="mined with status 0")
            raise TransactionReverted(hash_hex, receipt.blockNumber)

        block = self.w3.eth.get_block(receipt.blockNumber)
        self._update(transaction["transaction_hash"], status="SUCCESS",
                     block_number=receipt.blockNumber, gas_used=receipt.gasUsed,
                     confirmed_at=time.time(), block_timestamp=block["timestamp"])

        return {
            "transaction_hash": hash_hex,
            "block_number": receipt.blockNumber,
            "gas_used": receipt.gasUsed,
            "block_timestamp": block["timestamp"],
            "tx_status": "SUCCESS",
            "from_cache": False
        }



    def send(self, contract_function, idempotency_key=None):
        
        if not isinstance(idempotency_key, str) or not idempotency_key.strip():
            raise ValueError("A non-empty idempotency_key is required.")

        with self._nonce_lock:
            transaction = self._load_or_create_transaction(contract_function, idempotency_key)

            if transaction["status"] == "SUCCESS":
                return {
                    "transaction_hash": transaction["transaction_hash"],
                    "block_number": transaction["block_number"],
                    "gas_used": transaction["gas_used"],
                    "block_timestamp": transaction.get("block_timestamp"),
                    "tx_status": "SUCCESS",
                    "from_cache": True
                }

            return self._finish(transaction)

    def resume_pending(self):
        
        results = []
        with self._nonce_lock:
            with connect(DB_PATH) as db:
                rows = [dict(r) for r in db.execute("""
                    SELECT * FROM transactions
                    WHERE account = ? AND chain_id = ? AND status IN ('PREPARED', 'BROADCAST')
                    ORDER BY nonce
                """, (self.account.address.lower(), self.w3.eth.chain_id)).fetchall()]

            for row in rows:
                try:
                    results.append({"idempotency_key": row["idempotency_key"], **self._finish(row)})
                except Exception as exc:
                    results.append({"idempotency_key": row["idempotency_key"], "error": str(exc)})
        return results
