from web3 import Web3

from gateway.transactions import TransactionManager


def _hash32(value, field_name):
    if isinstance(value, str):
        try:
            value = bytes.fromhex(value.removeprefix("0x"))
        except ValueError as exc:
            raise ValueError(f"{field_name} must be hexadecimal") from exc

    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError(f"{field_name} must be exactly 32 bytes")

    if value == bytes(32):
        raise ValueError(f"{field_name} cannot be zero")

    return value


def _build_transaction(client, function):
    return function.build_transaction({
        "from": client.address,
        "chainId": client.w3.eth.chain_id,
        "gas": 3000000,
        "gasPrice": 0
    })

def _submit(client, function, idempotency_key):
    return TransactionManager(client).send(
        function,
        idempotency_key=idempotency_key
    )


def _recovery_contract(client):
    return client.get_contract("DeviceRecovery")


def submit_recovery_request(
    client,
    device_id,
    remediation_hash,
    ai_evaluation_hash,
    attestation_hash,
    recovery_evidence_hash
):
    device_id = _hash32(device_id, "device_id")
    remediation_hash = _hash32(remediation_hash, "remediation_hash")
    ai_evaluation_hash = _hash32(
        ai_evaluation_hash, "ai_evaluation_hash"
    )
    attestation_hash = _hash32(attestation_hash, "attestation_hash")
    recovery_evidence_hash = _hash32(
        recovery_evidence_hash, "recovery_evidence_hash"
    )

    contract = _recovery_contract(client)

    active_request = contract.functions.getActiveRequest(
        device_id
    ).call()

    if active_request != 0:
        raise ValueError(
            f"Device already has active recovery request {active_request}"
        )

    function = contract.functions.submitRecoveryRequest(
        device_id,
        remediation_hash,
        ai_evaluation_hash,
        attestation_hash,
        recovery_evidence_hash
    )

    result = _submit(
        client,
        function,
        "recovery-request:"
        + device_id.hex()
        + ":"
        + remediation_hash.hex()
        + ":"
        + ai_evaluation_hash.hex()
        + ":"
        + attestation_hash.hex()
        + ":"
        + recovery_evidence_hash.hex()
    )

    receipt = client.w3.eth.get_transaction_receipt(
        result["transaction_hash"]
    )

    events = contract.events.RecoveryRequested().process_receipt(
        receipt
    )

    if not events:
        raise RuntimeError(
            "Recovery request transaction succeeded but "
            "RecoveryRequested event was not found"
        )

    request_id = int(events[0]["args"]["requestId"])

    return {
        **result,
        "request_id": request_id,
        "device_id": "0x" + device_id.hex(),
        "requesting_domain": client.address
    }


def validate_recovery(client, request_id, approved):
    if not isinstance(request_id, int) or request_id <= 0:
        raise ValueError("request_id must be a positive integer")

    if not isinstance(approved, bool):
        raise ValueError("approved must be a boolean")

    contract = _recovery_contract(client)

    if contract.functions.hasValidated(
        request_id, client.address
    ).call():
        raise ValueError("This domain has already validated this request")

    function = contract.functions.validateRecovery(
        request_id, approved
    )

    return _submit(
        client,
        function,
        f"recovery-validation:{request_id}:{client.address.lower()}"
    )


def finalize_recovery(
    client,
    request_id,
    successful,
    final_assessment_hash
):
    if not isinstance(request_id, int) or request_id <= 0:
        raise ValueError("request_id must be a positive integer")

    if not isinstance(successful, bool):
        raise ValueError("successful must be a boolean")

    final_assessment_hash = _hash32(
        final_assessment_hash,
        "final_assessment_hash"
    )

    contract = _recovery_contract(client)

    function = contract.functions.finalizeRecovery(
        request_id,
        successful,
        final_assessment_hash
    )

    return _submit(
        client,
        function,
        f"recovery-finalize:{request_id}:"
        f"{successful}:{final_assessment_hash.hex()}"
    )


def expire_recovery_request(client, request_id):
    if not isinstance(request_id, int) or request_id <= 0:
        raise ValueError("request_id must be a positive integer")

    contract = _recovery_contract(client)

    return _submit(
        client,
        contract.functions.expireRequest(request_id),
        f"recovery-expire:{request_id}"
    )


def get_active_recovery_request(client, device_id):
    device_id = _hash32(device_id, "device_id")

    contract = _recovery_contract(client)
    request_id = contract.functions.getActiveRequest(
        device_id
    ).call()

    return int(request_id)


def get_recovery_request(client, request_id):
    if not isinstance(request_id, int) or request_id <= 0:
        raise ValueError("request_id must be a positive integer")

    contract = _recovery_contract(client)
    result = contract.functions.getRecoveryRequest(request_id).call()

    function_abi = next(
        item for item in contract.abi
        if item.get("type") == "function"
        and item.get("name") == "getRecoveryRequest"
    )

    components = function_abi["outputs"][0].get("components", [])

    if components:
        return {
            component["name"]: value
            for component, value in zip(components, result)
        }

    return result


def get_recovery_events(client, from_block=0, to_block="latest"):
    contract = _recovery_contract(client)

    if to_block == "latest":
        to_block = client.w3.eth.block_number

    event_names = [
        "RecoveryRequested",
        "RecoveryValidated",
        "RecoveryApproved",
        "RecoveryRejected",
        "RecoveryExpired",
        "RecoveryFinalized"
    ]

    result = {}

    for event_name in event_names:
        event_factory = getattr(contract.events, event_name)
        logs = []

        chunk_size = 500
        current_block = from_block

        while current_block <= to_block:
            end_block = min(current_block + chunk_size - 1, to_block)

            try:
                batch = event_factory().get_logs(
                    from_block=current_block,
                    to_block=end_block
                )
                logs.extend(batch)
                current_block = end_block + 1

            except Exception as exc:
                if chunk_size > 1:
                    chunk_size = max(1, chunk_size // 2)
                    continue

                raise RuntimeError(
                    f"Failed to retrieve {event_name} events "
                    f"from blocks {current_block} to {end_block}: {exc}"
                ) from exc

        result[event_name] = logs

    return result