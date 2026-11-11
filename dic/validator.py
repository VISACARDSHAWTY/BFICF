
from dic.models import IncidentRequest


def validate_incident(incident: IncidentRequest) -> dict:
    data = incident.model_dump()

    if not data["incident_vector"]:
        raise ValueError("Incident Vector cannot be empty")

    if not data["incident_id"].strip():
        raise ValueError("Incident ID cannot be empty")

    return data
