from web3 import Web3
from web3.logs import DISCARD

from gateway.hashing import commitment_bytes
from gateway.transactions import TransactionManager
from gateway.utils import to_hex, incident_id_hash, resource_id, get_event_logs


RESPONSE_ACTIONS = {"QUARANTINE": 0, "PATCH": 1, "REVOKE": 2, "BLOCK_TRAFFIC": 3, "MONITOR": 4}

ACTION_NAMES = {0: "QUARANTINE", 1: "PATCH", 2: "REVOKE", 3: "BLOCK_TRAFFIC", 4: "MONITOR", 5: "NO_ACTION"}
STATUS_NAMES = {0: "PENDING", 1: "APPROVED", 2: "REJECTED", 3: "EXPIRED"}


def _proposal_epoch(client, id_hash):
    contract = client.get_contract("ResponseProposal")
    epoch = 0
    for log in get_event_logs(client, "ResponseProposal", "ProposalCreated", {"incidentId": id_hash}):
        if contract.functions.proposals(log["args"]["proposalId"]).call()[7] != 0:
            epoch += 1
    return epoch


def create_response_proposal(client, incident_id, target_domain, target_resource,
                             actions, details, voting_duration=3600):
    if not incident_id:
        raise ValueError("Incident ID cannot be empty")

    if not actions or len(actions) > 6:
        raise ValueError("Provide between 1 and 6 response actions")

    normalized_actions = [a.upper() for a in actions]
    if len(set(normalized_actions)) != len(normalized_actions):
        raise ValueError("Duplicate response actions")
    if any(a not in RESPONSE_ACTIONS for a in normalized_actions):
        raise ValueError("Invalid response action")
    if not any(a != "BLOCK_TRAFFIC" for a in normalized_actions):
        raise ValueError("At least one primary response action is required")

    contract = client.get_contract("ResponseProposal")

    min_period = contract.functions.MIN_VOTING_PERIOD().call()
    max_period = contract.functions.MAX_VOTING_PERIOD().call()
    if not min_period <= voting_duration <= max_period:
        raise ValueError(f"Voting duration must be between {min_period}s and {max_period}s")

    if not isinstance(target_resource, str) or not target_resource:
        raise ValueError("Target resource cannot be empty")

    id_hash = incident_id_hash(incident_id)
    target_address = client.resolve_domain_address(target_domain)
    target_resource_hash = resource_id(target_resource)

    details_hash = bytes(Web3.keccak(details)) if isinstance(details, bytes) else commitment_bytes(details)
    if details_hash == bytes(32):
        raise ValueError("Invalid details hash")

    epoch = _proposal_epoch(client, id_hash)

    result = TransactionManager(client).send(
        contract.functions.createProposal(
            id_hash, target_address, target_resource_hash,
            [RESPONSE_ACTIONS[a] for a in normalized_actions], details_hash, voting_duration),
        idempotency_key=(
            f"proposal-create:{incident_id}:{target_address.lower()}:"
            f"{target_resource_hash.hex()}:{details_hash.hex()}:{epoch}"
        )
    )

    
    receipt = client.w3.eth.get_transaction_receipt(result["transaction_hash"])
    events = contract.events.ProposalCreated().process_receipt(receipt, errors=DISCARD)
    if not events:
        raise RuntimeError("Proposal transaction succeeded but ProposalCreated was not found")

    return {
        "proposal_id": int(events[0]["args"]["proposalId"]),
        "incident_id": incident_id,
        "target_domain": target_domain.upper() if isinstance(target_domain, str) else target_domain,
        "target_resource_hash": to_hex(target_resource_hash),
        "details_hash": to_hex(details_hash),
        "actions": normalized_actions,
        "voting_duration": voting_duration,
        **result
    }


def get_response_proposal(client, proposal_id):
    contract = client.get_contract("ResponseProposal")
    proposal = contract.functions.proposals(proposal_id).call()

    return {
        "proposal_id": proposal_id,
        "incident_id_hash": to_hex(proposal[0]),
        "proposer": proposal[1],
        "target_domain": proposal[2],
        "target_resource_hash": to_hex(proposal[3]),
        "details_hash": to_hex(proposal[4]),
        "created_at": proposal[5],
        "voting_deadline": proposal[6],
        "status": STATUS_NAMES[proposal[7]],
        "actions": [ACTION_NAMES[a] for a in contract.functions.getActions(proposal_id).call()],
        "eligible_voters": contract.functions.getEligibleVoters(proposal_id).call(),
        "voting_started": contract.functions.votingStarted(proposal_id).call(),
        "voting_open": contract.functions.isVotingOpen(proposal_id).call()
    }


def expire_proposal(client, proposal_id):
    """Anyone may call this once the deadline passed and voting never started: incident -> ESCALATED."""
    contract = client.get_contract("ResponseProposal")
    result = TransactionManager(client).send(
        contract.functions.expireProposal(proposal_id),
        idempotency_key=f"proposal-expire:{proposal_id}"
    )
    return {"proposal_id": proposal_id, "status": "EXPIRED", **result}
