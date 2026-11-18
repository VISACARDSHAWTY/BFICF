from web3 import Web3

from gateway.hashing import commitment_bytes
from gateway.transactions import TransactionManager
from gateway.utils import to_hex, incident_id_hash, get_event_logs, to_bytes32


INCIDENT_TYPES = {"SOFTWARE": 0, "HARDWARE": 1, "CYBER": 2}

INCIDENT_STATES = [
    "REGISTERED", "CORRELATED", "RESPONSE_PROPOSED", "VOTING",
    "APPROVED", "EXECUTING", "VERIFIED", "CLOSED", "ESCALATED"
]


def register_incident(client, incident_id, incident_vector, incident_type, severity, detected_at):
    if not incident_id:
        raise ValueError("Incident ID cannot be empty")

    incident_type = incident_type.upper()
    if incident_type not in INCIDENT_TYPES:
        raise ValueError("Invalid incident type")

    if not isinstance(severity, int) or not 0 <= severity <= 10:
        raise ValueError("Severity must be between 0 and 10")

    if not isinstance(detected_at, int) or detected_at <= 0:
        raise ValueError("Invalid detection timestamp")

    id_hash = incident_id_hash(incident_id)
    vector_commitment = commitment_bytes(incident_vector)

    contract = client.get_contract("IncidentRegistry")
    transaction = contract.functions.registerIncident(
        id_hash, vector_commitment, INCIDENT_TYPES[incident_type], severity, detected_at
    )

    result = TransactionManager(client).send(
        transaction, idempotency_key=f"incident-register:{incident_id}"
    )

    return {
        "incident_id": incident_id,
        "incident_id_hash": to_hex(id_hash),
        "vector_commitment": to_hex(vector_commitment),
        **result
    }


def get_incident(client, incident_id):
    contract = client.get_contract("IncidentRegistry")
    incident = contract.functions.incidents(incident_id_hash(incident_id)).call()

    if incident[4] == 0:
        raise ValueError("Incident not found")

    return {
        "incident_id": incident_id,
        "incident_id_hash": to_hex(incident_id_hash(incident_id)),
        "vector_commitment": to_hex(incident[0]),
        "incident_type": ["SOFTWARE", "HARDWARE", "CYBER"][incident[1]],
        "severity": incident[2],
        "detected_at": incident[3],
        "registered_at": incident[4],
        "state": INCIDENT_STATES[incident[5]],
        "registered_by": incident[6],
        "closure_hash": to_hex(incident[7]),
    }


def get_incident_state(client, incident_id):
    contract = client.get_contract("IncidentRegistry")
    return INCIDENT_STATES[contract.functions.stateOf(incident_id_hash(incident_id)).call()]


def _state_changes(client, incident_id):
    return get_event_logs(client, "IncidentRegistry", "IncidentStateUpdated",
                          {"incidentId": incident_id_hash(incident_id)})


def close_incident(client, incident_id, closure_record):
    if isinstance(closure_record, str) and closure_record.startswith("0x") and len(closure_record) == 66:
        closure_hash = to_bytes32(closure_record, "closure_record")
    elif isinstance(closure_record, (bytes, bytearray)):
        closure_hash = bytes(Web3.keccak(bytes(closure_record)))
    else:
        closure_hash = commitment_bytes(closure_record)

    contract = client.get_contract("IncidentRegistry")
    result = TransactionManager(client).send(
        contract.functions.closeIncident(incident_id_hash(incident_id), closure_hash),
        idempotency_key=f"incident-close:{incident_id}"
    )
    return {"incident_id": incident_id, "closure_hash": to_hex(closure_hash), "status": "CLOSED", **result}


def reopen_incident(client, incident_id):
    epoch = sum(1 for e in _state_changes(client, incident_id)
                if e["args"]["oldState"] == 8 and e["args"]["newState"] == 1)
    contract = client.get_contract("IncidentRegistry")
    result = TransactionManager(client).send(
        contract.functions.reopenIncident(incident_id_hash(incident_id)),
        idempotency_key=f"incident-reopen:{incident_id}:{epoch}"
    )
    return {"incident_id": incident_id, "status": "REOPENED", **result}


def force_escalate_approved(client, incident_id):
    epoch = sum(1 for e in _state_changes(client, incident_id) if e["args"]["newState"] == 8)
    contract = client.get_contract("IncidentRegistry")
    result = TransactionManager(client).send(
        contract.functions.forceEscalateApproved(incident_id_hash(incident_id)),
        idempotency_key=f"incident-force-escalate:{incident_id}:{epoch}"
    )
    return {"incident_id": incident_id, "status": "ESCALATED", **result}
