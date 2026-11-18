from web3.logs import DISCARD

from gateway.transactions import TransactionManager
from gateway.utils import to_hex, to_bytes32, get_event_logs
from gateway.devices import device_id as _device_id


def _hash32(value, field_name):
    return to_bytes32(value, field_name)


def _submit(client, function, idempotency_key):
    return TransactionManager(client).send(function, idempotency_key=idempotency_key)


def _recovery_contract(client):
    return client.get_contract("DeviceRecovery")


def _device_epoch(client, device_id):

    contract = _recovery_contract(client)
    epoch = 0
    for log in get_event_logs(client, "DeviceRecovery", "RecoveryRequested", {"deviceId": device_id}):
        status = contract.functions.recoveryRequests(log["args"]["requestId"]).call()[11]
        if status in (2, 3):
            epoch += 1
    return epoch


def submit_recovery_request(client, device_id, remediation_hash, ai_evaluation_hash,
                            attestation_hash, recovery_evidence_hash):
    device_id = _device_id(device_id)       # accepts a device name or a 0x…32-byte id
    remediation_hash = _hash32(remediation_hash, "remediation_hash")
    ai_evaluation_hash = _hash32(ai_evaluation_hash, "ai_evaluation_hash")
    attestation_hash = _hash32(attestation_hash, "attestation_hash")
    recovery_evidence_hash = _hash32(recovery_evidence_hash, "recovery_evidence_hash")

    contract = _recovery_contract(client)

    active_request = contract.functions.getActiveRequest(device_id).call()
    if active_request != 0:
        raise ValueError(f"Device already has active recovery request {active_request}")

    epoch = _device_epoch(client, device_id)

    result = _submit(
        client,
        contract.functions.submitRecoveryRequest(
            device_id, remediation_hash, ai_evaluation_hash, attestation_hash, recovery_evidence_hash),
        "recovery-request:" + ":".join(
            h.hex() for h in (device_id, remediation_hash, ai_evaluation_hash,
                              attestation_hash, recovery_evidence_hash)) + f":{epoch}"
    )

    receipt = client.w3.eth.get_transaction_receipt(result["transaction_hash"])
    events = contract.events.RecoveryRequested().process_receipt(receipt, errors=DISCARD)
    if not events:
        raise RuntimeError("Recovery request transaction succeeded but RecoveryRequested event was not found")

    return {
        **result,
        "request_id": int(events[0]["args"]["requestId"]),
        "device_id": to_hex(device_id),
        "requesting_domain": client.address
    }


def validate_recovery(client, request_id, approved):
    if not isinstance(request_id, int) or request_id <= 0:
        raise ValueError("request_id must be a positive integer")
    if not isinstance(approved, bool):
        raise ValueError("approved must be a boolean")

    contract = _recovery_contract(client)
    if contract.functions.hasValidated(request_id, client.address).call():
        raise ValueError("This domain has already validated this request")

    return _submit(client, contract.functions.validateRecovery(request_id, approved),
                   f"recovery-validation:{request_id}:{client.address.lower()}")


def finalize_recovery(client, request_id, successful, final_assessment_hash):

    if not isinstance(request_id, int) or request_id <= 0:
        raise ValueError("request_id must be a positive integer")
    if not isinstance(successful, bool):
        raise ValueError("successful must be a boolean")

    final_assessment_hash = _hash32(final_assessment_hash, "final_assessment_hash")
    contract = _recovery_contract(client)

    return _submit(
        client,
        contract.functions.finalizeRecovery(request_id, successful, final_assessment_hash),
        f"recovery-finalize:{request_id}:{successful}:{final_assessment_hash.hex()}"
    )


def expire_recovery_request(client, request_id):
    if not isinstance(request_id, int) or request_id <= 0:
        raise ValueError("request_id must be a positive integer")

    return _submit(client, _recovery_contract(client).functions.expireRequest(request_id),
                   f"recovery-expire:{request_id}")


def get_active_recovery_request(client, device_id):
    return int(_recovery_contract(client).functions.getActiveRequest(_device_id(device_id)).call())


def get_recovery_request(client, request_id):
    if not isinstance(request_id, int) or request_id <= 0:
        raise ValueError("request_id must be a positive integer")

    contract = _recovery_contract(client)
    result = contract.functions.getRecoveryRequest(request_id).call()

    function_abi = next(
        item for item in contract.abi
        if item.get("type") == "function" and item.get("name") == "getRecoveryRequest")
    components = function_abi["outputs"][0].get("components", [])

    if components:
        return {component["name"]: value for component, value in zip(components, result)}
    return result


def get_recovery_events(client, from_block=None, to_block=None):
    names = ["RecoveryRequested", "RecoveryValidated", "RecoveryApproved",
             "RecoveryRejected", "RecoveryExpired", "RecoveryFinalized"]
    return {n: get_event_logs(client, "DeviceRecovery", n, from_block=from_block, to_block=to_block)
            for n in names}
