from gateway.client import BlockchainClient

DOMAINS = ["OEM", "CLOUD", "EDGE", "USER", "SECAUTH"]

for domain in DOMAINS:
    try:
        client = BlockchainClient(domain)
        status = client.get_network_status()

        print(f"\nDOMAIN: {domain}")
        print(f"Connected: {status['connected']}")
        print(f"Account: {status['address']}")
        print(f"Chain ID: {status['chain_id']}")
        print(f"Block: {status['block_number']}")
        print(f"Balance: {status['balance']} ETH")

    except Exception as error:
        print(f"\nDOMAIN: {domain}")
        print(f"ERROR: {error}")