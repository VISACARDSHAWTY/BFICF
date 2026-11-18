from gateway.utils import to_hex

DECISION_OUTCOMES = {0: "QUARANTINE", 1: "PATCH", 2: "REVOKE", 3: "MONITOR", 4: "NO_ACTION", 5: "NO_QUORUM"}


def get_decision(client, proposal_id):
    d = client.get_contract("ResponseDecision").functions.decisions(proposal_id).call()
    if not d[5]:
        return {"proposal_id": proposal_id, "finalized": False}

    return {
        "proposal_id": proposal_id,
        "finalized": True,
        "outcome": DECISION_OUTCOMES[d[0]],
        "outcome_code": d[0],
        "valid_votes": d[1],
        "eligible_voters": d[2],
        "quorum_reached": d[3],
        "timestamp": d[4],
    }
