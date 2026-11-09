from gateway.event_listener import BlockchainEventListener


class DICEventBridge:
    """
    Routes persisted blockchain events to DIC application callbacks.

    Register callbacks using:
        bridge.register_handler("IncidentRegistry", "IncidentRegistered", callback)

    Each callback receives one event payload dictionary.
    """

    def __init__(self, listener):
        self.listener = listener
        self.handlers = {}
        self.registered_events = 0

    def register_handler(self, contract_name, event_name, callback):
        if not callable(callback):
            raise TypeError("callback must be callable")

        key = (contract_name, event_name)
        self.handlers.setdefault(key, []).append(callback)

        self.listener.subscribe(
            contract_name,
            event_name,
            self._dispatch(key)
        )

        self.registered_events += 1

    def _dispatch(self, key):
        def callback(payload):
            for handler in self.handlers.get(key, []):
                handler(payload)

        return callback

    def register_all_events(self, callback):
        """Send every deployed contract event to one DIC callback."""
        for contract_name, contract in self.listener.client.contracts.items():
            for item in contract.abi:
                if item.get("type") != "event":
                    continue

                self.register_handler(
                    contract_name,
                    item["name"],
                    callback
                )

    def start(self):
        self.listener.start()

    def stop(self):
        self.listener.stop()

    def poll_once(self):
        return self.listener.poll_once()

    def get_status(self):
        status = self.listener.get_status()
        status["registered_callbacks"] = self.registered_events
        return status
