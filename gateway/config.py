import os
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")         


def _required(name):
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing environment variable {name} (see .env.example)")
    return value


CHAIN_ID = int(_required("CHAIN_ID"))


NETWORK = os.getenv("NETWORK", "besu")                       
DEPLOYMENT_DIR = Path(os.getenv("DEPLOYMENT_DIR") or ROOT / "contracts" / "deployments")
DEPLOYMENT_FILE = DEPLOYMENT_DIR / f"{NETWORK}.json"
ABI_DIR = DEPLOYMENT_DIR / "abi"


GAS_PRICE = int(os.getenv("GAS_PRICE", "0"))              
GAS_MARGIN = float(os.getenv("GAS_MARGIN", "1.25"))        
GAS_FALLBACK = int(os.getenv("GAS_FALLBACK", "3000000"))   
GAS_LIMIT_CAP = int(os.getenv("GAS_LIMIT_CAP", "8000000"))  
RPC_TIMEOUT = int(os.getenv("RPC_TIMEOUT", "30"))


DATA_DIR = Path(os.getenv("GATEWAY_DATA_DIR") or ROOT / "data")


def _identity(name, node_dir, rpc_env, rpc_fallback=None):
    rpc = os.getenv(rpc_env)
    if not rpc and rpc_fallback:
        rpc = os.getenv(rpc_fallback)
    key = os.getenv(f"{name}_KEY_FILE")
    return {
        "rpc": rpc,
        "key": Path(key) if key else ROOT / "chain" / "nodes" / node_dir / "key",
    }


DOMAINS = {
    "OEM":     _identity("OEM", "oem", "OEM_RPC"),
    "CLOUD":   _identity("CLOUD", "cloud", "CLOUD_RPC"),
    "EDGE":    _identity("EDGE", "edge", "EDGE_RPC"),
    "USER":    _identity("USER", "user", "USER_RPC"),
    "SECAUTH": _identity("SECAUTH", "secauth", "SECAUTH_RPC"),
    "CORRELATOR":        _identity("CORRELATOR", "correlator", "CORRELATOR_RPC", "SECAUTH_RPC"),
    "RECOVERY_VERIFIER": _identity("RECOVERY_VERIFIER", "recovery_verifier", "RECOVERY_VERIFIER_RPC", "SECAUTH_RPC"),
}

ACTIVE_DOMAIN = os.getenv("ACTIVE_DOMAIN", "OEM")
