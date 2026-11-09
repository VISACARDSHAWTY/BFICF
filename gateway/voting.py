import secrets

from web3 import Web3
from gateway.transactions import TransactionManager


VOTE_CHOICES = {
    "QUARANTINE": 0,
    "PATCH": 1,
    "REVOKE": 2,
    "MONITOR": 3,
    "NO_ACTION": 4
}


def _get_contracts(client):
    return (
        client.get_contract("FederatedVoting"),
        client.get_contract("ResponseProposal")
    )


def _normalize_choice(choice):
    if isinstance(choice, str):
        choice = choice.upper()
        if choice not in VOTE_CHOICES:
            raise ValueError("Invalid vote choice")
        return VOTE_CHOICES[choice]

    if isinstance(choice, int) and 0 <= choice <= 4:
        return choice

    raise ValueError("Invalid vote choice")


def _normalize_salt(salt):
    if isinstance(salt, str):
        try:
            salt = bytes.fromhex(salt.removeprefix("0x"))
        except ValueError:
            raise ValueError("Salt must be valid hexadecimal")

    if not isinstance(salt, bytes) or len(salt) != 32:
        raise ValueError("Salt must be exactly 32 bytes")

    return salt


def start_voting(client, proposal_id):
    voting, proposal = _get_contracts(client)

    if not proposal.functions.isEligibleVoter(
        proposal_id, client.address
    ).call():
        raise ValueError("Current account is not eligible to vote")

    session = voting.functions.getSession(proposal_id).call()

    if session[0]:
        return {"proposal_id": proposal_id, "status": "ALREADY_STARTED"}

    result = TransactionManager(client).send(
        voting.functions.startVoting(proposal_id)
    )

    return {
        "proposal_id": proposal_id,
        "status": "STARTED",
        **result
    }


def commit_vote(client, proposal_id, choice, salt=None):
    choice_value = _normalize_choice(choice)
    voting, proposal = _get_contracts(client)

    if not proposal.functions.isEligibleVoter(
        proposal_id, client.address
    ).call():
        raise ValueError("Current account is not eligible to vote")

    session = voting.functions.getSession(proposal_id).call()

    if not session[0]:
        start_voting(client, proposal_id)
        session = voting.functions.getSession(proposal_id).call()

    if session[1]:
        raise ValueError("Voting has already been finalized")

    if voting.functions.hasCommitted(
        proposal_id, client.address
    ).call():
        raise ValueError("This account has already committed a vote")

    if salt is None:
        salt = secrets.token_bytes(32)
    else:
        salt = _normalize_salt(salt)

    commitment = voting.functions.computeCommitment(
        proposal_id,
        client.address,
        choice_value,
        salt
    ).call()

    result = TransactionManager(client).send(
        voting.functions.commitVote(proposal_id, commitment)
    )

    return {
        "proposal_id": proposal_id,
        "voter": client.address,
        "choice": list(VOTE_CHOICES.keys())[choice_value],
        "commitment": Web3.to_hex(commitment),
        "salt": Web3.to_hex(salt),
        "status": "COMMITTED",
        **result
    }


def reveal_vote(client, proposal_id, choice, salt):
    choice_value = _normalize_choice(choice)
    salt = _normalize_salt(salt)
    voting, proposal = _get_contracts(client)

    if not proposal.functions.isEligibleVoter(
        proposal_id, client.address
    ).call():
        raise ValueError("Current account is not eligible to vote")

    if not voting.functions.hasCommitted(
        proposal_id, client.address
    ).call():
        raise ValueError("No vote commitment exists")

    if voting.functions.hasRevealed(
        proposal_id, client.address
    ).call():
        raise ValueError("This account has already revealed its vote")

    expected = voting.functions.computeCommitment(
        proposal_id, client.address, choice_value, salt
    ).call()

    stored = voting.functions.voteCommitments(
        proposal_id, client.address
    ).call()

    if expected != stored:
        raise ValueError("Vote choice or salt does not match commitment")

    result = TransactionManager(client).send(
        voting.functions.revealVote(proposal_id, choice_value, salt)
    )

    return {
        "proposal_id": proposal_id,
        "voter": client.address,
        "choice": list(VOTE_CHOICES.keys())[choice_value],
        "status": "REVEALED",
        **result
    }


def get_voting_session(client, proposal_id):
    voting = client.get_contract("FederatedVoting")
    session = voting.functions.getSession(proposal_id).call()
    counts = voting.functions.getVoteCounts(proposal_id).call()
    choices = list(VOTE_CHOICES.keys())

    return {
        "proposal_id": proposal_id,
        "started": session[0],
        "finalized": session[1],
        "commit_end": session[2],
        "reveal_end": session[3],
        "eligible_count": session[4],
        "revealed_count": session[5],
        "quarantine_threshold": session[6],
        "revoke_threshold": session[7],
        "patch_threshold": session[8],
        "quorum_basis_points": session[9],
        "vote_counts": {
            choices[i]: counts[i] for i in range(5)
        }
    }


def finalize_voting(client, proposal_id):
    voting = client.get_contract("FederatedVoting")
    session = voting.functions.getSession(proposal_id).call()

    if not session[0]:
        raise ValueError("Voting has not started")

    if session[1]:
        raise ValueError("Voting is already finalized")

    result = TransactionManager(client).send(
        voting.functions.finalizeVoting(proposal_id)
    )

    return {
        "proposal_id": proposal_id,
        "status": "FINALIZED",
        **result
    }