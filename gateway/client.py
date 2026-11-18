import json

from web3 import Web3
from eth_account import Account
from web3.middleware import ExtraDataToPOAMiddleware

from gateway.config import (
    CHAIN_ID, DOMAINS, ROOT, DEPLOYMENT_FILE as _DEPLOYMENT_FILE, ABI_DIR, RPC_TIMEOUT
)

DEPLOYMENT_FILE = _DEPLOYMENT_FILE
ABI_DIRECTORY = ABI_DIR


class BlockchainClient:

    def __init__(self, domain):
        if domain not in DOMAINS:
            raise ValueError("Unknown domain")

        self.domain = domain
        self.config = DOMAINS[domain]

        rpc = self.config["rpc"]
        if not rpc:
            raise ValueError(f"No RPC URL configured for {domain} (set {domain}_RPC in .env)")

        self.w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": RPC_TIMEOUT}))
        self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

        if not self.w3.is_connected():
            raise ConnectionError(f"{domain} cannot connect to Besu at {rpc}")

        actual_chain_id = self.w3.eth.chain_id
        if actual_chain_id != CHAIN_ID:
            raise ValueError(f"Wrong chain ID: {actual_chain_id}")

        key_path = self.config["key"]
        if not key_path.is_file():
            raise FileNotFoundError(f"Missing key file: {key_path}")

        private_key = key_path.read_text(encoding="utf-8").strip()
        self.account = Account.from_key(private_key)
        self.address = self.account.address

        if not DEPLOYMENT_FILE.is_file():
            raise FileNotFoundError(f"Missing deployment file: {DEPLOYMENT_FILE}")

        with DEPLOYMENT_FILE.open("r", encoding="utf-8") as file:
            self.deployment = json.load(file)

        if int(self.deployment["chainId"]) != CHAIN_ID:
            raise ValueError("Deployment record has the wrong chain ID")

        self.contract_addresses = self.deployment["contracts"]

        self.deployment_block = int(self.deployment.get("deploymentBlock", 0))

        self.contracts = {}
        self.load_contracts()

    def load_contracts(self):
        for name, address in self.contract_addresses.items():
            abi_path = ABI_DIRECTORY / f"{name}.json"

            if not abi_path.is_file():
                raise FileNotFoundError(f"Missing ABI for {name}: {abi_path}")

            with abi_path.open("r", encoding="utf-8") as file:
                artifact = json.load(file)

            abi = artifact if isinstance(artifact, list) else artifact["abi"]
            checksum_address = Web3.to_checksum_address(address)

            code = self.w3.eth.get_code(checksum_address)
            if len(code) == 0:
                raise RuntimeError(f"No contract deployed at {name}: {address}")

            self.contracts[name] = self.w3.eth.contract(address=checksum_address, abi=abi)

    def get_contract(self, name):
        if name not in self.contracts:
            raise ValueError(f"Unknown contract: {name}")
        return self.contracts[name]


    def resolve_domain_address(self, domain):
        if not isinstance(domain, str):
            return Web3.to_checksum_address(domain)

        text = domain.strip()
        for key, value in self.deployment.get("accounts", {}).items():
            if key.lower() == text.lower():
                return Web3.to_checksum_address(value)

        if Web3.is_address(text):
            return Web3.to_checksum_address(text)

        registry = self.get_contract("DomainRegistry")
        for candidate in dict.fromkeys([text, text.upper(), text.capitalize(), text.lower()]):
            address = registry.functions.nameToAddress(Web3.keccak(text=candidate)).call()
            if int(address, 16) != 0:
                return Web3.to_checksum_address(address)

        raise ValueError(f"Unknown domain: {domain}")

    def chain_time(self):
        return self.w3.eth.get_block("latest")["timestamp"]

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
