from web3 import Web3

from gateway.hashing import commitment_bytes
from gateway.transactions import TransactionManager
from gateway.utils import to_hex, incident_id_hash, to_bytes32


CONFIDENCE_CLASSES = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "VERY_HIGH": 3}
CONFIDENCE_NAMES = {v: k for k, v in CONFIDENCE_CLASSES.items()}


def _pending(client, id_hash):
    p = client.get_contract("CorrelationDecision").functions.pending(id_hash).call()
    return {
        "result_hash": to_hex(p[0]), "algorithm_version_hash": to_hex(p[1]),
        "confidence": CONFIDENCE_NAMES[p[2]], "submitted_by": p[3], "submitted_at": p[4],
        "round": p[5], "attestations": p[6], "required": p[7], "active": p[8],
    }


def submit_correlation(client, incident_id, correlation_result, confidence,
                       affected_domains, algorithm_version):
    if confidence.upper() not in CONFIDENCE_CLASSES:
        raise ValueError("Invalid confidence class")

    if not affected_domains:
        raise ValueError("At least one affected domain is required")

    id_hash = incident_id_hash(incident_id)
    result_hash = commitment_bytes(correlation_result)
    algorithm_hash = bytes(Web3.keccak(text=algorithm_version))
    domain_addresses = [client.resolve_domain_address(d) for d in affected_domains]

    contract = client.get_contract("CorrelationDecision")
    next_round = _pending(client, id_hash)["round"] + 1     # a re-submission is a NEW round -> new key

    result = TransactionManager(client).send(
        contract.functions.submitCorrelation(
            id_hash, result_hash, CONFIDENCE_CLASSES[confidence.upper()],
            domain_addresses, algorithm_hash),
        idempotency_key=f"correlation-submit:{incident_id}:{result_hash.hex()}:{next_round}"
    )

    return {
        "incident_id": incident_id,
        "result_hash": to_hex(result_hash),
        "algorithm_version_hash": to_hex(algorithm_hash),
        "confidence": confidence.upper(),
        "affected_domains": affected_domains,
        "round": next_round,
        **result
    }


def attest_correlation(client, incident_id, result_hash):
    id_hash = incident_id_hash(incident_id)
    result_hash_bytes = to_bytes32(result_hash, "result_hash")
    round_number = _pending(client, id_hash)["round"]

    contract = client.get_contract("CorrelationDecision")
    return TransactionManager(client).send(
        contract.functions.attestCorrelation(id_hash, result_hash_bytes),
        idempotency_key=f"correlation-attest:{incident_id}:{round_number}:{result_hash_bytes.hex()}"
    )


def get_correlation_status(client, incident_id):
    id_hash = incident_id_hash(incident_id)
    contract = client.get_contract("CorrelationDecision")

    recorded = contract.functions.correlations(id_hash).call()
    status = {
        "incident_id": incident_id,
        "pending": _pending(client, id_hash),
        "finalized": bool(recorded[5]),
        "pending_affected_domains": contract.functions.getPendingAffectedDomains(id_hash).call(),
    }
    if recorded[5]:
        status["result"] = {
            "result_hash": to_hex(recorded[0]), "algorithm_version_hash": to_hex(recorded[1]),
            "confidence": CONFIDENCE_NAMES[recorded[2]], "timestamp": recorded[3],
            "submitted_by": recorded[4],
        }
        status["affected_domains"] = contract.functions.getAffectedDomains(id_hash).call()
    return status
