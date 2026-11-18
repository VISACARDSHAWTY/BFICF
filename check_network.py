from gateway.client import BlockchainClient
from gateway.config import DOMAINS
from gateway import domains

for name in DOMAINS:
    try:
        client = BlockchainClient(name)
        status = client.get_network_status()

        print(f"\nDOMAIN: {name}")
        print(f"Connected: {status['connected']}")
        print(f"Account: {status['address']}")
        print(f"Chain ID: {status['chain_id']}")
        print(f"Block: {status['block_number']}")
        print(f"Balance: {status['balance']} ETH")
        print(f"Contracts loaded: {status['contracts_loaded']}")
        print(f"Roles: active_domain={domains.is_active_domain(client)} "
              f"correlator={domains.is_correlator(client)} "
              f"security_authority={domains.is_security_authority(client)}")

    except Exception as error:
        print(f"\nDOMAIN: {name}")
        print(f"ERROR: {error}")
