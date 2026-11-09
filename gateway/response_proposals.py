from web3 import Web3

from gateway.hashing import generate_commitment
from gateway.transactions import TransactionManager


RESPONSE_ACTIONS = {
    "QUARANTINE": 0,
    "PATCH": 1,
    "REVOKE": 2,
    "BLOCK_TRAFFIC": 3,
    "MONITOR": 4
}

MIN_VOTING_PERIOD = 300
MAX_VOTING_PERIOD = 604800


def create_response_proposal(
    client,
    incident_id,
    target_domain,
    target_resource,
    actions,
    details,
    voting_duration=3600
):
    if not incident_id:
        raise ValueError("Incident ID cannot be empty")

    target_domain = target_domain.upper()

    if target_domain.lower() not in client.deployment["accounts"]:
        raise ValueError("Invalid target domain")

    if not actions or len(actions) > 6:
        raise ValueError("Provide between 1 and 6 response actions")

    normalized_actions = [action.upper() for action in actions]

    if len(set(normalized_actions)) != len(normalized_actions):
        raise ValueError("Duplicate response actions")

    if any(action not in RESPONSE_ACTIONS for action in normalized_actions):
        raise ValueError("Invalid response action")

    if not any(action != "BLOCK_TRAFFIC" for action in normalized_actions):
        raise ValueError("At least one primary response action is required")

    if not MIN_VOTING_PERIOD <= voting_duration <= MAX_VOTING_PERIOD:
        raise ValueError("Voting duration must be between 5 minutes and 7 days")

    if not isinstance(target_resource, str) or not target_resource:
        raise ValueError("Target resource cannot be empty")

    incident_id_hash = Web3.keccak(text=incident_id)

    target_address = Web3.to_checksum_address(
        client.deployment["accounts"][target_domain.lower()]
    )

    target_resource_hash = Web3.keccak(text=target_resource)

    if isinstance(details, bytes):
        details_hash = Web3.keccak(details)
    else:
        details_hash = bytes.fromhex(
            generate_commitment(details).removeprefix("0x")
        )

    if details_hash == bytes(32):
        raise ValueError("Invalid details hash")

    action_values = [
        RESPONSE_ACTIONS[action] for action in normalized_actions
    ]

    contract = client.get_contract("ResponseProposal")

    proposal_id = contract.functions.nextProposalId().call()

    transaction = contract.functions.createProposal(
        incident_id_hash,
        target_address,
        target_resource_hash,
        action_values,
        details_hash,
        voting_duration
    )

    result = TransactionManager(client).send(
        transaction,
        idempotency_key=(
            f"proposal-create:{incident_id}:"
            f"{target_domain}:{target_resource_hash.hex()}:"
            f"{details_hash.hex()}"
        )
    )

    return {
        "proposal_id": proposal_id,
        "incident_id": incident_id,
        "target_domain": target_domain,
        "target_resource_hash": target_resource_hash.hex(),
        "details_hash": Web3.to_hex(details_hash),
        "actions": normalized_actions,
        "voting_duration": voting_duration,
        **result
    }


def get_response_proposal(client, proposal_id):
    contract = client.get_contract("ResponseProposal")

    proposal = contract.functions.proposals(proposal_id).call()

    status_names = {
        0: "PENDING",
        1: "APPROVED",
        2: "REJECTED",
        3: "EXPIRED"
    }

    action_names = {
        0: "QUARANTINE",
        1: "PATCH",
        2: "REVOKE",
        3: "BLOCK_TRAFFIC",
        4: "MONITOR",
        5: "NO_ACTION"
    }

    actions = contract.functions.getActions(proposal_id).call()
    voters = contract.functions.getEligibleVoters(proposal_id).call()

    return {
        "proposal_id": proposal_id,
        "incident_id_hash": Web3.to_hex(proposal[0]),
        "proposer": proposal[1],
        "target_domain": proposal[2],
        "target_resource_hash": Web3.to_hex(proposal[3]),
        "details_hash": Web3.to_hex(proposal[4]),
        "created_at": proposal[5],
        "voting_deadline": proposal[6],
        "status": status_names[proposal[7]],
        "actions": [action_names[action] for action in actions],
        "eligible_voters": voters,
        "voting_started": contract.functions.votingStarted(proposal_id).call(),
        "voting_open": contract.functions.isVotingOpen(proposal_id).call()
    }