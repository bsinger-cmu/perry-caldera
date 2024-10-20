from plugins.deception.app.actions.HighLevelAction import HighLevelAction
from plugins.deception.app.models.events import Event
from plugins.deception.app.models.network import Host
from plugins.deception.app.services import (
    LowLevelActionOrchestrator,
    EnvironmentStateService,
    AttackGraphService,
)


class EscelatePrivledge(HighLevelAction):
    def __init__(self, host: Host):
        self.host = host

    async def run(
        self,
        low_level_action_orchestrator: LowLevelActionOrchestrator,
        environment_state_service: EnvironmentStateService,
        attack_graph_service: AttackGraphService,
    ) -> list[Event]:
        events = []

        # TODO: Implement EscelatePrivledge action

        return events
