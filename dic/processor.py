
from dic.validator import validate_incident
from dic.classifier import classify_incident
from dic.store import save_incident
from gateway.incidents import register_incident
from gateway.client import BlockchainClient


def process_incident(incident, domain: str) -> dict:
    data = validate_incident(incident)

    classification = classify_incident(data)

    client = BlockchainClient(domain)

    result = register_incident(
        client=client,
        incident_id=data["incident_id"],
        incident_vector=data["incident_vector"],
        incident_type=data["incident_type"],
        severity=data["severity"],
        detected_at=data["detected_at"]
    )

    response = {
        "incident_id": data["incident_id"],
        "domain": domain,
        "incident_type": data["incident_type"],
        "classification": classification,
        "severity": data["severity"],
        "detected_at": data["detected_at"],
        "incident_vector": data["incident_vector"],
        "vector_commitment": result["vector_commitment"],
        "transaction_hash": result["transaction_hash"],
        "block_number": result["block_number"],
        "status": "REGISTERED"
    }

    save_incident(response)

    return response
