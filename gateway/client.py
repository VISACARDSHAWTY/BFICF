from web3 import Web3
from eth_account import Account
from gateway.config import CHAIN_ID, DOMAINS


class BlockchainClient:
    def __init__(self, domain):
        if domain not in DOMAINS:
            raise ValueError("Unknown domain")

        self.domain = domain
        self.config = DOMAINS[domain]

        self.w3 = Web3(
            Web3.HTTPProvider(self.config["rpc"])
        )

        if not self.w3.is_connected():
            raise ConnectionError(
                f"{domain} cannot connect to Besu"
            )

        actual_chain_id = self.w3.eth.chain_id

        if actual_chain_id != CHAIN_ID:
            raise ValueError(
                f"Wrong chain ID: {actual_chain_id}"
            )

        key_path = self.config["key"]

        if not key_path.is_file():
            raise FileNotFoundError(
                f"Missing key file: {key_path}"
            )

        private_key = key_path.read_text(
            encoding="utf-8"
        ).strip()

        self.account = Account.from_key(private_key)
        self.address = self.account.address

    def get_block_number(self):
        return self.w3.eth.block_number

    def get_balance(self):
        balance = self.w3.eth.get_balance(self.address)
        return self.w3.from_wei(balance, "ether")

    def get_network_status(self):
        return {
            "domain": self.domain,
            "address": self.address,
            "connected": self.w3.is_connected(),
            "chain_id": self.w3.eth.chain_id,
            "block_number": self.get_block_number(),
            "balance": str(self.get_balance())
        }