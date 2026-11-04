import os
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

CHAIN_ID = int(os.getenv("CHAIN_ID"))

DOMAINS = {
    "OEM": {
        "rpc": os.getenv("OEM_RPC"),
        "key": ROOT / "chain/nodes/oem/key"
    },
    "CLOUD": {
        "rpc": os.getenv("CLOUD_RPC"),
        "key": ROOT / "chain/nodes/cloud/key"
    },
    "EDGE": {
        "rpc": os.getenv("EDGE_RPC"),
        "key": ROOT / "chain/nodes/edge/key"
    },
    "USER": {
        "rpc": os.getenv("USER_RPC"),
        "key": ROOT / "chain/nodes/user/key"
    },
    "SECAUTH": {
        "rpc": os.getenv("SECAUTH_RPC"),
        "key": ROOT / "chain/nodes/secauth/key"
    }
}

ACTIVE_DOMAIN = os.getenv("ACTIVE_DOMAIN", "OEM")