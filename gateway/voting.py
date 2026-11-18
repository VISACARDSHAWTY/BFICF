import secrets

from web3 import Web3

from gateway.config import DATA_DIR
from gateway.db import connect
from gateway.transactions import TransactionManager
from gateway.utils import to_hex

VOTE_CHOICES = {"QUARANTINE": 0, "PATCH": 1, "REVOKE": 2, "MONITOR": 3, "NO_ACTION": 4}
CHOICE_NAMES = list(VOTE_CHOICES.keys())

SALT_DB = DATA_DIR / "vote_salts.sqlite3"


def _get_contracts(client):
    return client.get_contract("FederatedVoting"), client.get_contract("ResponseProposal")


def _normalize_choice(choice):
    if isinstance(choice, str):
        choice = choice.upper()
        if choice not in VOTE_CHOICES:
            raise ValueError("Invalid vote choice")
        return VOTE_CHOICES[choice]

    if isinstance(choice, int) and not isinstance(choice, bool) and 0 <= choice <= 4:
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


def _init_salt_db(db):
    db.execute("""
        CREATE TABLE IF NOT EXISTS vote_salts (
            chain_id INTEGER NOT NULL,
            proposal_id INTEGER NOT NULL,
            voter TEXT NOT NULL,
            choice INTEGER NOT NULL,
            salt BLOB NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (chain_id, proposal_id, voter)
        )
    """)


def _load_or_create_vote_salt(client, proposal_id, choice_value, supplied_salt=None, allow_replace=False):

    chain_id = client.w3.eth.chain_id
    voter = client.address.lower()

    with connect(SALT_DB) as db:
        _init_salt_db(db)
        db.execute("BEGIN IMMEDIATE")

        row = db.execute(
            "SELECT choice, salt FROM vote_salts WHERE chain_id = ? AND proposal_id = ? AND voter = ?",
            (chain_id, proposal_id, voter)).fetchone()

        if row:
            stored_choice, stored_salt = row["choice"], bytes(row["salt"])

            if stored_choice == choice_value:
                if supplied_salt is not None and supplied_salt != stored_salt:
                    raise ValueError("Supplied salt does not match the stored vote salt")
                return stored_salt

            if not allow_replace:
                raise ValueError(
                    "A vote salt already exists for this proposal and account with a different choice")

            db.execute("DELETE FROM vote_salts WHERE chain_id = ? AND proposal_id = ? AND voter = ?",
                       (chain_id, proposal_id, voter))

        salt = supplied_salt or secrets.token_bytes(32)
        db.execute(
            "INSERT INTO vote_salts (chain_id, proposal_id, voter, choice, salt) VALUES (?, ?, ?, ?, ?)",
            (chain_id, proposal_id, voter, choice_value, salt))
        return salt


def get_stored_vote(client, proposal_id):
    with connect(SALT_DB) as db:
        _init_salt_db(db)
        row = db.execute(
            "SELECT choice, salt FROM vote_salts WHERE chain_id = ? AND proposal_id = ? AND voter = ?",
            (client.w3.eth.chain_id, proposal_id, client.address.lower())).fetchone()
    return (CHOICE_NAMES[row["choice"]], bytes(row["salt"])) if row else None


def start_voting(client, proposal_id):
    voting, proposal = _get_contracts(client)

    if not proposal.functions.isEligibleVoter(proposal_id, client.address).call():
        raise ValueError("Current account is not eligible to vote")

    if voting.functions.getSession(proposal_id).call()[0]:
        return {"proposal_id": proposal_id, "status": "ALREADY_STARTED"}

    result = TransactionManager(client).send(
        voting.functions.startVoting(proposal_id),
        idempotency_key=f"voting-start:{proposal_id}"
    )
    return {"proposal_id": proposal_id, "status": "STARTED", **result}


def commit_vote(client, proposal_id, choice, salt=None, include_salt=False):
    choice_value = _normalize_choice(choice)
    voting, proposal = _get_contracts(client)

    if not proposal.functions.isEligibleVoter(proposal_id, client.address).call():
        raise ValueError("Current account is not eligible to vote")

    session = voting.functions.getSession(proposal_id).call()
    if not session[0]:
        start_voting(client, proposal_id)
        session = voting.functions.getSession(proposal_id).call()

    if session[1]:
        raise ValueError("Voting has already been finalized")

    committed = voting.functions.hasCommitted(proposal_id, client.address).call()
    supplied_salt = _normalize_salt(salt) if salt is not None else None

    salt_bytes = _load_or_create_vote_salt(
        client, proposal_id, choice_value, supplied_salt, allow_replace=not committed)

    commitment = voting.functions.computeCommitment(
        proposal_id, client.address, choice_value, salt_bytes).call()

    base = {
        "proposal_id": proposal_id,
        "voter": client.address,
        "choice": CHOICE_NAMES[choice_value],
        "commitment": to_hex(commitment),
    }
    if include_salt:
        base["salt"] = to_hex(salt_bytes)

    if committed:
        stored = voting.functions.voteCommitments(proposal_id, client.address).call()
        if stored != commitment:
            raise ValueError("An existing vote commitment does not match the locally stored vote")
        return {**base, "status": "ALREADY_COMMITTED"}

    result = TransactionManager(client).send(
        voting.functions.commitVote(proposal_id, commitment),
        idempotency_key=f"vote-commit:{proposal_id}:{client.address.lower()}"
    )
    return {**base, "status": "COMMITTED", **result}


def reveal_vote(client, proposal_id, choice=None, salt=None):
    if choice is None or salt is None:
        stored = get_stored_vote(client, proposal_id)
        if stored is None:
            raise ValueError("No locally stored vote for this proposal; pass choice and salt explicitly")
        choice = stored[0] if choice is None else choice
        salt = stored[1] if salt is None else salt

    choice_value = _normalize_choice(choice)
    salt = _normalize_salt(salt)
    voting, proposal = _get_contracts(client)

    if not proposal.functions.isEligibleVoter(proposal_id, client.address).call():
        raise ValueError("Current account is not eligible to vote")
    if not voting.functions.hasCommitted(proposal_id, client.address).call():
        raise ValueError("No vote commitment exists")
    if voting.functions.hasRevealed(proposal_id, client.address).call():
        raise ValueError("This account has already revealed its vote")

    expected = voting.functions.computeCommitment(proposal_id, client.address, choice_value, salt).call()
    if expected != voting.functions.voteCommitments(proposal_id, client.address).call():
        raise ValueError("Vote choice or salt does not match commitment")

    result = TransactionManager(client).send(
        voting.functions.revealVote(proposal_id, choice_value, salt),
        idempotency_key=f"vote-reveal:{proposal_id}:{client.address.lower()}"
    )
    return {"proposal_id": proposal_id, "voter": client.address,
            "choice": CHOICE_NAMES[choice_value], "status": "REVEALED", **result}


def get_voting_session(client, proposal_id):
    voting = client.get_contract("FederatedVoting")
    session = voting.functions.getSession(proposal_id).call()
    counts = voting.functions.getVoteCounts(proposal_id).call()

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
        "vote_counts": {CHOICE_NAMES[i]: counts[i] for i in range(5)}
    }


def can_finalize(client, proposal_id):
    session = client.get_contract("FederatedVoting").functions.getSession(proposal_id).call()
    if not session[0] or session[1]:
        return False, None
    remaining = max(0, session[3] - client.chain_time())
    return remaining == 0, remaining


def finalize_voting(client, proposal_id):
    voting = client.get_contract("FederatedVoting")
    session = voting.functions.getSession(proposal_id).call()

    if not session[0]:
        raise ValueError("Voting has not started")
    if session[1]:
        raise ValueError("Voting is already finalized")

    result = TransactionManager(client).send(
        voting.functions.finalizeVoting(proposal_id),
        idempotency_key=f"voting-finalize:{proposal_id}"
    )
    return {"proposal_id": proposal_id, "status": "FINALIZED", **result}
