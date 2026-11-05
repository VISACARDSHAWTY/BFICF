from web3 import Web3

from gateway.hashing import generate_commitment
from gateway.transactions import TransactionManager


INCIDENT_TYPES = {
    "SOFTWARE": 0,
    "HARDWARE": 1,
    "CYBER": 2
}


def register_incident(
    client,
    incident_id,
    incident_vector,
    incident_type,
    severity,
    detected_at
):
    if not incident_id:
        raise ValueError("Incident ID cannot be empty")

    incident_type = incident_type.upper()

    if incident_type not in INCIDENT_TYPES:
        raise ValueError("Invalid incident type")

    if not isinstance(severity, int) or not 0 <= severity <= 10:
        raise ValueError("Severity must be between 0 and 10")

    if not isinstance(detected_at, int) or detected_at <= 0:
        raise ValueError("Invalid detection timestamp")

    incident_id_hash = Web3.keccak(
        text=incident_id
    )

    vector_commitment = bytes.fromhex(
        generate_commitment(incident_vector).removeprefix("0x")
    )

    contract = client.get_contract("IncidentRegistry")

    transaction = contract.functions.registerIncident(
        incident_id_hash,
        vector_commitment,
        INCIDENT_TYPES[incident_type],
        severity,
        detected_at
    )

    result = TransactionManager(client).send(transaction)

    return {
        "incident_id": incident_id,
        "incident_id_hash": incident_id_hash.hex(),
        "vector_commitment": vector_commitment.hex(),
        **result
    }