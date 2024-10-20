from plugins.deception.app.data.attacker_config import AttackerConfig, Environment
from plugins.deception.app.models.network import Network, Subnet
import os
import json


class EnvironmentInitializer:
    def __init__(self):
        # Check if config.json exists
        if not os.path.exists("plugins/deception/app/data/config.json"):
            raise FileNotFoundError("config.json not found")

        # Load config.json
        with open("plugins/deception/app/data/config.json", "r") as f:
            config = f.read()
            json_config = json.loads(config)

        self.attacker_config = AttackerConfig(**json_config)

    def get_initial_environment_state(self):
        if self.attacker_config.environment == Environment.EQUIFAX_LARGE.value:
            # In Equifax, attacker knows external subnet
            network = Network([Subnet("192.168.200.0/24")])
            return network
        elif self.attacker_config.environment == Environment.ICS.value:
            # In ICS, attacker has no initial network knowledge
            return Network([])
        elif self.attacker_config.environment == Environment.RING.value:
            # In ring, attacker has no initial network knowledge
            return Network([])

        return Network([])
