from gateway.hashing import commitment_bytes
from gateway.transactions import TransactionManager
from gateway.utils import to_hex, to_bytes32, resource_id, get_event_logs

DEVICE_STATES = ["ACTIVE", "QUARANTINED", "RECOVERING", "REVOKED"]


def device_id(device):
    
    if isinstance(device, (bytes, bytearray)) or (isinstance(device, str) and device.startswith("0x") and len(device) == 66):
        return to_bytes32(device, "device")
    return resource_id(device)


def _contract(client):
    return client.get_contract("DeviceRegistry")


def register_device(client, device, metadata=None):
    dev = device_id(device)
    metadata_hash = commitment_bytes(metadata if metadata is not None else {"device": to_hex(dev)})

    result = TransactionManager(client).send(
        _contract(client).functions.registerDevice(dev, metadata_hash),
        idempotency_key=f"device-register:{dev.hex()}"
    )
    return {"device_id": to_hex(dev), "metadata_hash": to_hex(metadata_hash), "status": "REGISTERED", **result}


def quarantine_device(client, device, reason):
    dev = device_id(device)
    reason_hash = commitment_bytes(reason)

    epoch = len(get_event_logs(client, "DeviceRegistry", "DeviceQuarantined", {"deviceId": dev}))
    result = TransactionManager(client).send(
        _contract(client).functions.quarantineDevice(dev, reason_hash),
        idempotency_key=f"device-quarantine:{dev.hex()}:{epoch}"
    )
    return {"device_id": to_hex(dev), "reason_hash": to_hex(reason_hash), "status": "QUARANTINED", **result}


def apply_decision(client, device, proposal_id):
    dev = device_id(device)
    result = TransactionManager(client).send(
        _contract(client).functions.applyDecision(dev, proposal_id),
        idempotency_key=f"device-apply:{dev.hex()}:{proposal_id}"
    )
    return {"device_id": to_hex(dev), "proposal_id": proposal_id, "status": "DECISION_APPLIED", **result}


def revoke_device(client, device):
    dev = device_id(device)
    result = TransactionManager(client).send(
        _contract(client).functions.revokeDevice(dev),
        idempotency_key=f"device-revoke:{dev.hex()}"
    )
    return {"device_id": to_hex(dev), "status": "REVOKED", **result}


def get_device(client, device):
    dev = device_id(device)
    d = _contract(client).functions.getDevice(dev).call()
    return {
        "device_id": to_hex(d[0]), "owning_domain": d[1], "metadata_hash": to_hex(d[2]),
        "registered_at": d[3], "state": DEVICE_STATES[d[4]],
    }
