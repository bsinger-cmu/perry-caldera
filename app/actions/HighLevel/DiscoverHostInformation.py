from ..HighLevelAction import HighLevelAction
from ..LowLevel.ListFilesInDirectory import ListFilesInDirectory
from ..LowLevel.FindSSHConfig import FindSSHConfig

from plugins.deception.app.models.network import Host
from plugins.deception.app.models.events import Event, CriticalDataFound, FilesFound
from plugins.deception.app.services import (
    LowLevelActionOrchestrator,
    EnvironmentStateService,
    AttackGraphService,
)
from plugins.deception.app.helpers.logging import log_event


class DiscoverHostInformation(HighLevelAction):
    def __init__(self, host: Host):
        self.host = host

    async def run(
        self,
        low_level_action_orchestrator: LowLevelActionOrchestrator,
        environment_state_service: EnvironmentStateService,
        attack_graph_service: AttackGraphService,
    ) -> list[Event]:
        """
        _try_reading_user_flags
        @brief: tries to read flag.txt in each user's home directory
        @param agent: agent that will try to read flag.txt
        """
        events: list[Event] = []
        agent = self.host.get_agent()
        if not agent:
            log_event("DiscoverHostInformation", f"No agent found for host {self.host}")
            raise Exception(f"No agent found for host {self.host}")

        new_events = await low_level_action_orchestrator.run_action(
            FindSSHConfig(agent, self.host)
        )
        events += new_events

        # First try to find all user directories
        user_home_dir = f"/home/{agent.username}/"
        new_events = await low_level_action_orchestrator.run_action(
            ListFilesInDirectory(agent, user_home_dir)
        )
        for event in new_events:
            if isinstance(event, FilesFound):
                critical_filepaths = []
                for filepath in event.files:
                    if "json" in filepath:
                        if filepath not in critical_filepaths:
                            critical_filepaths.append(filepath)

                if len(critical_filepaths) > 0:
                    events.append(CriticalDataFound(self.host, critical_filepaths))

        return events
