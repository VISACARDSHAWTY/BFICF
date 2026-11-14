
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Literal, Any
from collections.abc import Mapping

from dic.models import IncidentRequest
from dic.processor import process_incident
from dic.store import initialize_store, get_incident

from gateway.incidents import get_incident as get_blockchain_incident
from gateway.voting import commit_vote, reveal_vote, get_voting_session, finalize_voting, reveal_vote_from_store
from gateway.client import BlockchainClient


from gateway.execution import (
    create_execution_plan,
    get_execution_action,
    report_execution,
    attest_action,
    get_execution_progress,
    escalate_stalled_execution,
)

from gateway.recovery import (
    submit_recovery_request,
    validate_recovery,
    finalize_recovery,
    expire_recovery_request,
    get_active_recovery_request,
    get_recovery_request,
    get_recovery_events,
)

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
    
class ExecutionActionRequest(BaseModel):
    responsible_domain: str
    action: Literal[
        "QUARANTINE",
        "PATCH",
        "REVOKE",
        "BLOCK_TRAFFIC",
        "MONITOR",
    ]
    details: Any


class ExecutionPlanRequest(BaseModel):
    proposal_id: int = Field(gt=0)
    actions: list[ExecutionActionRequest]


class ExecutionReceiptRequest(BaseModel):
    receipt: Any


class ExecutionAttestationRequest(BaseModel):
    valid: bool


class RecoveryRequest(BaseModel):
    device_id: str
    remediation_hash: str
    ai_evaluation_hash: str
    attestation_hash: str
    recovery_evidence_hash: str


class RecoveryValidationRequest(BaseModel):
    approved: bool


class RecoveryFinalizationRequest(BaseModel):
    successful: bool
    final_assessment_hash: str

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
    

@app.post("/execution/plan")
def create_execution(request: ExecutionPlanRequest, domain: str = "OEM"):
    try:
        client = BlockchainClient(domain.upper())
        actions = [item.model_dump() for item in request.actions]
        return create_execution_plan(client, request.proposal_id, actions)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/execution/action/{action_id}")
def retrieve_execution_action(action_id: int, domain: str = "OEM"):
    try:
        client = BlockchainClient(domain.upper())
        return get_execution_action(client, action_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/execution/action/{action_id}/receipt")
def submit_execution_receipt(
    action_id: int,
    request: ExecutionReceiptRequest,
    domain: str = "OEM"
):
    try:
        client = BlockchainClient(domain.upper())
        return report_execution(client, action_id, request.receipt)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/execution/action/{action_id}/attest")
def attest_execution(
    action_id: int,
    request: ExecutionAttestationRequest,
    domain: str = "SECAUTH"
):
    try:
        client = BlockchainClient(domain.upper())
        return attest_action(client, action_id, request.valid)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/execution/proposal/{proposal_id}")
def retrieve_execution_progress(proposal_id: int, domain: str = "OEM"):
    try:
        client = BlockchainClient(domain.upper())
        return get_execution_progress(client, proposal_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/execution/proposal/{proposal_id}/escalate")
def escalate_execution(proposal_id: int, domain: str = "OEM"):
    try:
        client = BlockchainClient(domain.upper())
        return escalate_stalled_execution(client, proposal_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/recovery")
def create_recovery_request(
    request: RecoveryRequest,
    domain: str = "OEM"
):
    try:
        client = BlockchainClient(domain.upper())
        return submit_recovery_request(
            client,
            request.device_id,
            request.remediation_hash,
            request.ai_evaluation_hash,
            request.attestation_hash,
            request.recovery_evidence_hash
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/recovery/{request_id}/validate")
def validate_recovery_request(
    request_id: int,
    request: RecoveryValidationRequest,
    domain: str = "SECAUTH"
):
    try:
        client = BlockchainClient(domain.upper())
        return validate_recovery(client, request_id, request.approved)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/recovery/{request_id}/finalize")
def finalize_recovery_request(
    request_id: int,
    request: RecoveryFinalizationRequest,
    domain: str = "SECAUTH"
):
    try:
        client = BlockchainClient(domain.upper())
        return finalize_recovery(
            client,
            request_id,
            request.successful,
            request.final_assessment_hash
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/recovery/{request_id}/expire")
def expire_recovery(request_id: int, domain: str = "SECAUTH"):
    try:
        client = BlockchainClient(domain.upper())
        return expire_recovery_request(client, request_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/recovery/active/{device_id}")
def retrieve_active_recovery(device_id: str, domain: str = "OEM"):
    try:
        client = BlockchainClient(domain.upper())
        return {
            "device_id": device_id,
            "request_id": get_active_recovery_request(client, device_id)
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@app.get("/recovery/events")
def retrieve_recovery_events(
    from_block: int = 0,
    domain: str = "OEM"
):
    try:
        client = BlockchainClient(domain.upper())
        events = get_recovery_events(client, from_block=from_block)

        def make_json_safe(value):
            if isinstance(value, (bytes, bytearray, memoryview)):
                return "0x" + bytes(value).hex()

            if isinstance(value, Mapping):
                return {
                    str(make_json_safe(key)): make_json_safe(item)
                    for key, item in value.items()
                }

            if isinstance(value, (list, tuple)):
                return [make_json_safe(item) for item in value]

            if hasattr(value, "hex") and not isinstance(value, str):
                try:
                    return value.hex()
                except Exception:
                    pass

            if value is None or isinstance(value, (str, int, float, bool)):
                return value

            return str(value)

        return JSONResponse(content=make_json_safe(events))

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    
@app.get("/recovery/{request_id}")
def retrieve_recovery_request(request_id: int, domain: str = "OEM"):
    try:
        client = BlockchainClient(domain.upper())
        return get_recovery_request(client, request_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


