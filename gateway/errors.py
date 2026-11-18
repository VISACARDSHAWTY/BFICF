class GatewayError(RuntimeError):
    '''base class for all errors'''


class GatewayRevert(GatewayError):
    

    def __init__(self, reason, function=None):
        self.reason = reason
        self.function = function
        super().__init__(f"{function or 'call'} would revert: {reason}")


class TransactionReverted(GatewayError):

    def __init__(self, tx_hash, block_number):
        self.tx_hash = tx_hash
        self.block_number = block_number
        super().__init__(f"Transaction reverted. Hash: {tx_hash}, block: {block_number}")


class TransactionTimeout(GatewayError, TimeoutError):
    """Broadcast succeeded but no receipt arrived in time. Retry with the same idempotency key."""
