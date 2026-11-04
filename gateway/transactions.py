class TransactionManager:
    def __init__(self, client):
        self.client = client
        self.w3 = client.w3
        self.account = client.account

    def send(self, contract_function):
        nonce = self.w3.eth.get_transaction_count(
            self.account.address, "pending"
        )

        transaction = contract_function.build_transaction({
            "from": self.account.address,
            "nonce": nonce,
            "chainId": self.w3.eth.chain_id,
            "gasPrice": 0,
            "gas": 3000000
        })

        signed = self.account.sign_transaction(transaction)

        tx_hash = self.w3.eth.send_raw_transaction(
            signed.raw_transaction
        )

        receipt = self.w3.eth.wait_for_transaction_receipt(
            tx_hash, timeout=120
        )

        if receipt.status != 1:
            raise RuntimeError(
                f"Transaction failed: {tx_hash.hex()}"
            )

        return {
            "transaction_hash": tx_hash.hex(),
            "block_number": receipt.blockNumber,
            "gas_used": receipt.gasUsed,
            "status": "SUCCESS"
        }