
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
        db = sqlite3.connect(DB_PATH, timeout=30)
        db.row_factory = sqlite3.Row
        return db

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
                    nonce INTEGER,
                    chain_id INTEGER,
                    PRIMARY KEY (account, idempotency_key)
                )
            """)

            columns = {
                row["name"]
                for row in db.execute(
                    "PRAGMA table_info(transactions)"
                ).fetchall()
            }

            if "nonce" not in columns:
                db.execute(
                    "ALTER TABLE transactions ADD COLUMN nonce INTEGER"
                )

            if "chain_id" not in columns:
                db.execute(
                    "ALTER TABLE transactions ADD COLUMN chain_id INTEGER"
                )

            db.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS
                idx_transactions_account_chain_nonce
                ON transactions(account, chain_id, nonce)
                WHERE nonce IS NOT NULL
            """)

    def _request_hash(self, contract_function):
        chain_id = self.w3.eth.chain_id
        contract_address = getattr(contract_function, "address", "")
        calldata = contract_function._encode_transaction_data()

        payload = {
            "chain_id": chain_id,
            "sender": self.account.address.lower(),
            "contract": str(contract_address).lower(),
            "calldata": calldata,
            "value": 0
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
        account = self.account.address.lower()
        chain_id = self.w3.eth.chain_id

        with self._connect() as db:
            # Serializes nonce reservation across gateway processes.
            db.execute("BEGIN IMMEDIATE")

            existing = db.execute("""
                SELECT *
                FROM transactions
                WHERE account = ? AND idempotency_key = ?
            """, (account, idempotency_key)).fetchone()

            if existing:
                if existing["request_hash"] != request_hash:
                    raise ValueError(
                        "This idempotency key was already used "
                        "for a different transaction."
                    )

                return dict(existing)

            pending_nonce = self.w3.eth.get_transaction_count(
                self.account.address,
                "pending"
            )

            last_reserved = db.execute("""
                SELECT MAX(nonce) AS last_nonce
                FROM transactions
                WHERE account = ? AND chain_id = ?
            """, (account, chain_id)).fetchone()["last_nonce"]

            nonce = pending_nonce

            if last_reserved is not None:
                nonce = max(nonce, last_reserved + 1)

            transaction = contract_function.build_transaction({
                "from": self.account.address,
                "nonce": nonce,
                "chainId": chain_id,
                "gasPrice": 0,
                "gas": 3000000
            })

            signed = self.account.sign_transaction(transaction)
            tx_hash = signed.hash.hex()
            raw_transaction = signed.raw_transaction.hex()

            db.execute("""
                INSERT INTO transactions (
                    account,
                    idempotency_key,
                    request_hash,
                    transaction_hash,
                    raw_transaction,
                    status,
                    created_at,
                    nonce,
                    chain_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                account,
                idempotency_key,
                request_hash,
                tx_hash,
                raw_transaction,
                "PREPARED",
                int(time.time()),
                nonce,
                chain_id
            ))

            return {
                "transaction_hash": tx_hash,
                "raw_transaction": raw_transaction,
                "status": "PREPARED",
                "nonce": nonce,
                "chain_id": chain_id
            }

    def _update_status(self, transaction_hash, status):
        with self._connect() as db:
            db.execute("""
                UPDATE transactions
                SET status = ?
                WHERE transaction_hash = ?
            """, (status, transaction_hash))

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

                self._update_status(expected_hash, "BROADCAST")
                return tx_hash

            except Exception as exc:
                message = str(exc).lower()

                if "already known" in message:
                    self._update_status(expected_hash, "BROADCAST")
                    return Web3.to_bytes(hexstr=expected_hash)

                if "nonce too low" in message:
                    try:
                        receipt = self.w3.eth.get_transaction_receipt(
                            expected_hash
                        )
                        return receipt.transactionHash

                    except TransactionNotFound:
                        try:
                            self.w3.eth.get_transaction(expected_hash)
                            self._update_status(expected_hash, "BROADCAST")
                            return Web3.to_bytes(hexstr=expected_hash)

                        except TransactionNotFound:
                            raise RuntimeError(
                                "The transaction nonce was consumed, "
                                "but this transaction was not found. "
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
        delay = self.poll_interval
        last_error = None

        while time.monotonic() < deadline:
            try:
                return self.w3.eth.get_transaction_receipt(tx_hash)

            except TransactionNotFound:
                time.sleep(delay)

            except Exception as exc:
                # Keep polling through temporary RPC/provider errors.
                last_error = exc
                time.sleep(delay)

            delay = min(delay * 1.5, 10)

        message = (
            "Transaction was broadcast but no receipt was found. "
            f"Hash: {tx_hash.hex()}"
        )

        if last_error:
            message += f" Last RPC error: {last_error}"

        raise TimeoutError(message)

    def send(self, contract_function, idempotency_key=None):
        if (
            not isinstance(idempotency_key, str)
            or not idempotency_key.strip()
        ):
            raise ValueError(
                "A non-empty idempotency_key is required."
            )

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

            if transaction["status"] == "REVERTED":
                raise RuntimeError(
                    "This transaction previously reverted. "
                    f"Hash: {transaction['transaction_hash']}"
                )

            tx_hash = self._broadcast(transaction)
            receipt = self._wait_for_receipt(tx_hash)

            if receipt.status != 1:
                self._update_status(
                    transaction["transaction_hash"],
                    "REVERTED"
                )

                raise RuntimeError(
                    f"Transaction reverted. Hash: {tx_hash.hex()}, "
                    f"block: {receipt.blockNumber}"
                )

            with self._connect() as db:
                db.execute("""
                    UPDATE transactions
                    SET status = ?,
                        block_number = ?,
                        gas_used = ?
                    WHERE account = ? AND idempotency_key = ?
                """, (
                    "SUCCESS",
                    receipt.blockNumber,
                    receipt.gasUsed,
                    self.account.address.lower(),
                    idempotency_key
                ))

            return {
                "transaction_hash": tx_hash.hex(),
                "block_number": receipt.blockNumber,
                "gas_used": receipt.gasUsed,
                "status": "SUCCESS"
            }
