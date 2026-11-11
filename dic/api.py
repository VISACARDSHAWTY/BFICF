
from fastapi import FastAPI, HTTPException

from dic.models import IncidentRequest
from dic.processor import process_incident
from dic.store import initialize_store, get_incident

from gateway.incidents import get_incident as get_blockchain_incident
from gateway.client import BlockchainClient
app = FastAPI(title="BFICF Domain Incident Coordinator")

initialize_store()


@app.get("/health")
def health_check():
    return {"status": "healthy"}


@app.post("/incident")
def submit_incident(
    incident: IncidentRequest,
    domain: str = "OEM"
):
    try:
        return process_incident(incident, domain.upper())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/incident/{incident_id}")
def retrieve_incident(incident_id: str):
    incident = get_incident(incident_id)

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    return incident

@app.get("/incident/{incident_id}/blockchain")
def retrieve_blockchain_incident(incident_id: str, domain: str = "OEM"):
    try:
        client = BlockchainClient(domain.upper())
        return get_blockchain_incident(client, incident_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))