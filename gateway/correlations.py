from web3 import Web3

from gateway.hashing import generate_commitment
from gateway.transactions import TransactionManager


CONFIDENCE_CLASSES = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "VERY_HIGH": 3
}


def submit_correlation(
    client,
    incident_id,
    correlation_result,
    confidence,
    affected_domains,
    algorithm_version
):
    if confidence.upper() not in CONFIDENCE_CLASSES:
        raise ValueError("Invalid confidence class")

    if not affected_domains:
        raise ValueError("At least one affected domain is required")

    incident_id_hash = Web3.keccak(text=incident_id)

    result_hash = bytes.fromhex(
        generate_commitment(correlation_result).removeprefix("0x")
    )

    algorithm_hash = Web3.keccak(text=algorithm_version)

    domain_registry = client.get_contract("DomainRegistry")

    domain_addresses = []

    for domain in affected_domains:
        address = client.deployment["accounts"][domain.lower()]
        domain_addresses.append(Web3.to_checksum_address(address))

    contract = client.get_contract("CorrelationDecision")

    transaction = contract.functions.submitCorrelation(
        incident_id_hash,
        result_hash,
        CONFIDENCE_CLASSES[confidence.upper()],
        domain_addresses,
        algorithm_hash
    )

    result = TransactionManager(client).send(
        transaction,
        idempotency_key=f"correlation-submit:{incident_id}:{result_hash.hex()}"
    )

    return {
        "incident_id": incident_id,
        "result_hash": result_hash.hex(),
        "algorithm_version_hash": algorithm_hash.hex(),
        "confidence": confidence.upper(),
        "affected_domains": affected_domains,
        **result
    }


def attest_correlation(client, incident_id, result_hash):
    incident_id_hash = Web3.keccak(text=incident_id)

    result_hash_bytes = bytes.fromhex(
        result_hash.removeprefix("0x")
    )

    contract = client.get_contract("CorrelationDecision")

    transaction = contract.functions.attestCorrelation(
        incident_id_hash,
        result_hash_bytes
    )

    return TransactionManager(client).send(
        transaction,
        idempotency_key=f"correlation-attest:{incident_id}:{result_hash_bytes.hex()}"
    )