import re

from plugins.deception.app.actions.HighLevelAction import HighLevelAction
from plugins.deception.app.actions.LowLevel import (
    GetSudoVersion,
    CheckSudoersPermissions,
    SudoeditExploit,
    WriteableSudoersExploit,
)
from plugins.deception.app.models.events import Event, WriteableSudoers, SudoVersion
from plugins.deception.app.models.network import Host
from plugins.deception.app.services import (
    LowLevelActionOrchestrator,
    EnvironmentStateService,
    AttackGraphService,
)


def parse_version(version: str):
    """Convert version string to integer."""
    return int(re.sub(r"\D", "", version))


def is_older_version(version, reference="1.9"):
    """Compare two version strings to see if the first is older."""
    parsed_version = parse_version(version)
    parsed_reference = parse_version(reference)

    # Compare parsed versions
    return parsed_version < parsed_reference


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
        # Check if the host has a root user
        for agent in self.host.agents:
            if agent.username == "root":
                # If the host has a root user, we can skip this action
                return []

        if len(self.host.agents) == 0:
            # If there are no agents on the host, we can skip this action
            return []

        agent = self.host.agents[0]

        # See if sudoers is writeable
        events = await low_level_action_orchestrator.run_action(
            CheckSudoersPermissions(agent)
        )
        if len(events) > 0 and isinstance(events[0], WriteableSudoers):
            # If sudoers is writeable, we can exploit it
            return await low_level_action_orchestrator.run_action(
                WriteableSudoersExploit(agent)
            )

        # If sudoers is not writeable, we can try to exploit sudoedit
        events = await low_level_action_orchestrator.run_action(GetSudoVersion(agent))
        for event in events:
            if isinstance(event, SudoVersion):
                sudo_version = event.version
                break

        # Check if the sudo version is vulnerable
        if is_older_version(sudo_version, "1.8.30"):
            # If the sudo version is older than 1.9.11, we can exploit sudoedit
            return await low_level_action_orchestrator.run_action(
                SudoeditExploit(agent)
            )

        return []
