
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Literal

from dic.models import IncidentRequest
from dic.processor import process_incident
from dic.store import initialize_store, get_incident

from gateway.incidents import get_incident as get_blockchain_incident
from gateway.voting import commit_vote, reveal_vote, get_voting_session, finalize_voting, reveal_vote_from_store
from gateway.client import BlockchainClient

class VoteCommitRequest(BaseModel):
    proposal_id: int = Field(gt=0)
    choice: Literal[
        "QUARANTINE",
        "PATCH",
        "REVOKE",
        "MONITOR",
        "NO_ACTION"
    ]

class VoteRevealRequest(BaseModel):
    proposal_id: int = Field(gt=0)
    choice: Literal[
        "QUARANTINE",
        "PATCH",
        "REVOKE",
        "MONITOR",
        "NO_ACTION"
    ]
    
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
    
@app.post("/vote/commit")
def submit_vote_commit(
    request: VoteCommitRequest,
    domain: str = "OEM"
):
    try:
        client = BlockchainClient(domain.upper())

        result = commit_vote(
            client=client,
            proposal_id=request.proposal_id,
            choice=request.choice
        )

        result.pop("salt", None)
        return result

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    
@app.post("/vote/reveal")
def submit_vote_reveal(
    request: VoteRevealRequest,
    domain: str = "OEM"
):
    try:
        client = BlockchainClient(domain.upper())

        return reveal_vote_from_store(
            client=client,
            proposal_id=request.proposal_id,
            choice=request.choice
        )

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    
@app.get("/vote/{proposal_id}")
def retrieve_voting_session(
    proposal_id: int,
    domain: str = "OEM"
):
    try:
        client = BlockchainClient(domain.upper())
        return get_voting_session(client, proposal_id)

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    
@app.post("/vote/{proposal_id}/finalize")
def finalize_vote_session(
    proposal_id: int,
    domain: str = "SECAUTH"
):
    try:
        client = BlockchainClient(domain.upper())
        return finalize_voting(client, proposal_id)

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    
