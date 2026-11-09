from web3 import Web3

from gateway.hashing import generate_commitment
from gateway.transactions import TransactionManager


def commit_evidence(client, incident_id, evidence):
    if not incident_id:
        raise ValueError("Incident ID cannot be empty")

    if not isinstance(evidence, (dict, list, str, bytes)):
        raise ValueError("Unsupported evidence format")

    if isinstance(evidence, bytes):
        evidence_hash = Web3.keccak(evidence)
    else:
        evidence_hash = bytes.fromhex(
            generate_commitment(evidence).removeprefix("0x")
        )

    incident_id_hash = Web3.keccak(text=incident_id)

    contract = client.get_contract("EvidenceCommitment")

    transaction = contract.functions.commitEvidence(
        incident_id_hash,
        evidence_hash
    )

    result = TransactionManager(client).send(transaction)

    return {
        "incident_id": incident_id,
        "evidence_hash": evidence_hash.hex(),
        **result
    }


def verify_evidence(client, incident_id, evidence_hash):
    incident_id_hash = Web3.keccak(text=incident_id)

    evidence_hash_bytes = bytes.fromhex(
        evidence_hash.removeprefix("0x")
    )

    contract = client.get_contract("EvidenceCommitment")

    return contract.functions.verifyEvidence(
        incident_id_hash,
        evidence_hash_bytes
    ).call()