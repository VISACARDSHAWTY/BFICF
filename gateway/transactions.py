
import json
import sqlite3
import threading
import time
from pathlib import Path

from web3 import Web3
from web3.exceptions import TransactionNotFound


ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "data" / "transactions.sqlite3"


class TransactionManager:
    _account_locks = {}
    _lock_guard = threading.Lock()

    def __init__(
        self,
        client,
        receipt_timeout=120,
        poll_interval=2,
        max_broadcast_attempts=4
    ):
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

        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_database()

    def _connect(self):
        connection = sqlite3.connect(DB_PATH, timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize_database(self):
        with self._connect() as db:
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
                    PRIMARY KEY (account, idempotency_key)
                )
            """)

    def _request_hash(self, contract_function):
        contract_address = getattr(
            contract_function, "address", ""
        )

        calldata = contract_function._encode_transaction_data()

        payload = {
            "contract": str(contract_address).lower(),
            "calldata": calldata
        }

        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":")
        ).encode("utf-8")

        return Web3.keccak(encoded).hex()

    def _load_or_create_transaction(
        self,
        contract_function,
        idempotency_key
    ):
        request_hash = self._request_hash(contract_function)

        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")

            existing = db.execute(
                """
                SELECT * FROM transactions
                WHERE account = ? AND idempotency_key = ?
                """,
                (self.account.address.lower(), idempotency_key)
            ).fetchone()

            if existing:
                if existing["request_hash"] != request_hash:
                    raise ValueError(
                        "This idempotency key was already used "
                        "for a different transaction."
                    )

                return dict(existing)

            nonce = self.w3.eth.get_transaction_count(
                self.account.address,
                "pending"
            )

            transaction = contract_function.build_transaction({
                "from": self.account.address,
                "nonce": nonce,
                "chainId": self.w3.eth.chain_id,
                "gasPrice": 0,
                "gas": 3000000
            })

            signed = self.account.sign_transaction(transaction)
            tx_hash = signed.hash.hex()
            raw_transaction = signed.raw_transaction.hex()

            db.execute(
                """
                INSERT INTO transactions (
                    account,
                    idempotency_key,
                    request_hash,
                    transaction_hash,
                    raw_transaction,
                    status,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    self.account.address.lower(),
                    idempotency_key,
                    request_hash,
                    tx_hash,
                    raw_transaction,
                    "PREPARED",
                    int(time.time())
                )
            )

            return {
                "transaction_hash": tx_hash,
                "raw_transaction": raw_transaction,
                "status": "PREPARED"
            }

    def _broadcast(self, transaction):
        raw_transaction = bytes.fromhex(
            transaction["raw_transaction"].removeprefix("0x")
        )

        expected_hash = transaction["transaction_hash"]

        for attempt in range(self.max_broadcast_attempts):
            try:
                tx_hash = self.w3.eth.send_raw_transaction(
                    raw_transaction
                )
                return tx_hash

            except Exception as exc:
                message = str(exc).lower()

                if "already known" in message:
                    return Web3.to_bytes(hexstr=expected_hash)

                if "nonce too low" in message:
                    try:
                        self.w3.eth.get_transaction_receipt(
                            expected_hash
                        )
                        return Web3.to_bytes(hexstr=expected_hash)
                    except TransactionNotFound:
                        raise RuntimeError(
                            "Transaction nonce was already consumed, "
                            "but its receipt was not found. "
                            f"Hash: {expected_hash}"
                        ) from exc

                if attempt == self.max_broadcast_attempts - 1:
                    raise RuntimeError(
                        "Transaction broadcast remains uncertain. "
                        "Retry using the same idempotency key. "
                        f"Transaction hash: {expected_hash}. "
                        f"Error: {exc}"
                    ) from exc

                time.sleep(2 ** attempt)

        raise RuntimeError("Transaction broadcast failed.")

    def _wait_for_receipt(self, tx_hash):
        deadline = time.monotonic() + self.receipt_timeout

        while time.monotonic() < deadline:
            try:
                return self.w3.eth.get_transaction_receipt(tx_hash)
            except TransactionNotFound:
                time.sleep(self.poll_interval)

        raise TimeoutError(
            "Transaction was broadcast but no receipt was found. "
            f"Transaction hash: {tx_hash.hex()}"
        )

    def send(self, contract_function, idempotency_key=None):
        if idempotency_key is None:
            raise ValueError(
                "An idempotency_key is required for transaction submission."
            )

        if not isinstance(idempotency_key, str) or not idempotency_key.strip():
            raise ValueError("idempotency_key must be a non-empty string.")

        with self._nonce_lock:
            transaction = self._load_or_create_transaction(
                contract_function,
                idempotency_key
            )

            if transaction["status"] == "SUCCESS":
                return {
                    "transaction_hash": transaction["transaction_hash"],
                    "block_number": transaction["block_number"],
                    "gas_used": transaction["gas_used"],
                    "status": "SUCCESS"
                }

            tx_hash = self._broadcast(transaction)
            receipt = self._wait_for_receipt(tx_hash)

            if receipt.status != 1:
                raise RuntimeError(
                    f"Transaction reverted. Hash: {tx_hash.hex()}, "
                    f"block: {receipt.blockNumber}"
                )

            with self._connect() as db:
                db.execute(
                    """
                    UPDATE transactions
                    SET status = ?, block_number = ?, gas_used = ?
                    WHERE account = ? AND idempotency_key = ?
                    """,
                    (
                        "SUCCESS",
                        receipt.blockNumber,
                        receipt.gasUsed,
                        self.account.address.lower(),
                        idempotency_key
                    )
                )

            return {
                "transaction_hash": tx_hash.hex(),
                "block_number": receipt.blockNumber,
                "gas_used": receipt.gasUsed,
                "status": "SUCCESS"
            }
