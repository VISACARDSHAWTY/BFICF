from web3 import Web3

from gateway.hashing import commitment_bytes
from gateway.transactions import TransactionManager
from gateway.utils import to_hex, incident_id_hash, to_bytes32


def evidence_hash(evidence):
    if isinstance(evidence, (bytes, bytearray)):
        return bytes(Web3.keccak(bytes(evidence)))
    if isinstance(evidence, str):
        return bytes(Web3.keccak(text=evidence))
    if isinstance(evidence, (dict, list)):
        return commitment_bytes(evidence)
    raise ValueError("Unsupported evidence format")


def commit_evidence(client, incident_id, evidence):
    if not incident_id:
        raise ValueError("Incident ID cannot be empty")

    digest = evidence_hash(evidence)
    contract = client.get_contract("EvidenceCommitment")

    result = TransactionManager(client).send(
        contract.functions.commitEvidence(incident_id_hash(incident_id), digest),
        idempotency_key=f"evidence-commit:{incident_id}:{digest.hex()}"
    )

    return {"incident_id": incident_id, "evidence_hash": to_hex(digest), **result}


def verify_evidence(client, incident_id, evidence_hash_value):
    contract = client.get_contract("EvidenceCommitment")
    return contract.functions.verifyEvidence(
        incident_id_hash(incident_id), to_bytes32(evidence_hash_value, "evidence_hash")
    ).call()


def verify_evidence_data(client, incident_id, evidence):
    return verify_evidence(client, incident_id, to_hex(evidence_hash(evidence)))


def incident_has_evidence(client, incident_id):
    return client.get_contract("EvidenceCommitment").functions.incidentHasEvidence(
        incident_id_hash(incident_id)).call()


def get_evidence_count(client, incident_id):
    return client.get_contract("EvidenceCommitment").functions.evidenceCount(
        incident_id_hash(incident_id)).call()
