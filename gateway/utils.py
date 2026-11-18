from web3 import Web3


def to_hex(value):
    """Always '0x'-prefixed lowercase hex (HexBytes.hex() has no prefix in recent hexbytes)."""
    if isinstance(value, str):
        return value if value.startswith("0x") else "0x" + value
    return Web3.to_hex(bytes(value))


def to_bytes32(value, field="value", allow_zero=False):
    if isinstance(value, str):
        try:
            value = bytes.fromhex(value.removeprefix("0x"))
        except ValueError as exc:
            raise ValueError(f"{field} must be hexadecimal") from exc
    if not isinstance(value, (bytes, bytearray)) or len(value) != 32:
        raise ValueError(f"{field} must be exactly 32 bytes")
    value = bytes(value)
    if not allow_zero and value == bytes(32):
        raise ValueError(f"{field} cannot be zero")
    return value


def incident_id_hash(incident_id):
    """On-chain incident key = keccak256(utf8(incident_id))."""
    if not incident_id or not isinstance(incident_id, str):
        raise ValueError("Incident ID cannot be empty")
    return Web3.keccak(text=incident_id)


def resource_id(name):
    """On-chain resource / device key = keccak256(utf8(name)).
    Use the SAME function for proposals (targetResourceId) and devices (deviceId):
    DeviceRegistry.applyDecision only matches when they are identical."""
    if not name or not isinstance(name, str):
        raise ValueError("Resource name cannot be empty")
    return Web3.keccak(text=name)


def get_event_logs(client, contract_name, event_name, argument_filters=None,
                   from_block=None, to_block=None, chunk=2000):
    """eth_getLogs in chunks (nodes cap the block range); halves the chunk on RPC errors."""
    factory = getattr(client.get_contract(contract_name).events, event_name)
    current = client.deployment_block if from_block is None else from_block
    end = client.w3.eth.block_number if to_block is None else to_block
    size, logs = chunk, []

    while current <= end:
        stop = min(current + size - 1, end)
        try:
            logs.extend(factory().get_logs(
                from_block=current, to_block=stop,
                argument_filters=argument_filters or None))
            current = stop + 1
        except Exception:
            if size == 1:
                raise
            size = max(1, size // 2)
    return logs
