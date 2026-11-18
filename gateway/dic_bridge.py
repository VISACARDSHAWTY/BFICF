from gateway.event_listener import BlockchainEventListener


class DICEventBridge:


    def __init__(self, listener):
        self.listener = listener
        self.handlers = {}
        self.registered_events = 0

    def register_handler(self, contract_name, event_name, callback, handler_id=None):
        if not callable(callback):
            raise TypeError("callback must be callable")

        self.listener.subscribe(contract_name, event_name, callback, handler_id=handler_id)
        self.handlers.setdefault((contract_name, event_name), []).append(callback)
        self.registered_events += 1

    def register_all_events(self, callback):
        for contract_name, contract in self.listener.client.contracts.items():
            for item in contract.abi:
                if item.get("type") != "event":
                    continue
                self.register_handler(contract_name, item["name"], callback,
                                      handler_id=f"all:{contract_name}.{item['name']}")

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
