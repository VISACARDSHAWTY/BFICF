
import json
from pathlib import Path

from web3 import Web3
from eth_account import Account

from gateway.config import CHAIN_ID, DOMAINS, ROOT


DEPLOYMENT_FILE = (
    ROOT / "contracts" / "deployments" / "besu.json"
)

ABI_DIRECTORY = (
    ROOT / "contracts" / "deployments" / "abi"
)


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

        if not DEPLOYMENT_FILE.is_file():
            raise FileNotFoundError(
                f"Missing deployment file: {DEPLOYMENT_FILE}"
            )

        with DEPLOYMENT_FILE.open(
            "r", encoding="utf-8"
        ) as file:
            self.deployment = json.load(file)

        if int(self.deployment["chainId"]) != CHAIN_ID:
            raise ValueError(
                "Deployment record has the wrong chain ID"
            )

        self.contract_addresses = (
            self.deployment["contracts"]
        )

        self.contracts = {}
        self.load_contracts()

    def load_contracts(self):
        for name, address in self.contract_addresses.items():

            abi_path = ABI_DIRECTORY / f"{name}.json"

            if not abi_path.is_file():
                raise FileNotFoundError(
                    f"Missing ABI for {name}: {abi_path}"
                )

            with abi_path.open(
                "r", encoding="utf-8"
            ) as file:
                artifact = json.load(file)

            abi = artifact if isinstance(artifact, list) else artifact["abi"]

            checksum_address = Web3.to_checksum_address(
                address
            )

            contract = self.w3.eth.contract(
                address=checksum_address,
                abi=abi
            )

            code = self.w3.eth.get_code(
                checksum_address
            )

            if len(code) == 0:
                raise RuntimeError(
                    f"No contract deployed at {name}: {address}"
                )

            self.contracts[name] = contract

    def get_contract(self, name):
        if name not in self.contracts:
            raise ValueError(
                f"Unknown contract: {name}"
            )

        return self.contracts[name]

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
            "balance": str(self.get_balance()),
            "contracts_loaded": len(self.contracts),
            "contract_names": list(self.contracts.keys())
        }
