from plugins.deception.app.helpers.logging import log_event

from plugins.deception.app.models.network import AttackPath
from ..HighLevelAction import HighLevelAction
from ..LowLevel import ExploitStruts, SSHLateralMove, NCLateralMove
from plugins.deception.app.models.events import InfectedNewHost, Event
from plugins.deception.app.services import (
    LowLevelActionOrchestrator,
    EnvironmentStateService,
    AttackGraphService,
)


class AttackPathLateralMove(HighLevelAction):
    def __init__(self, attack_path: AttackPath, skip_if_already_executed: bool = False):
        self.attack_path = attack_path
        self.skip_if_already_executed = skip_if_already_executed

    async def run(
        self,
        low_level_action_orchestrator: LowLevelActionOrchestrator,
        environment_state_service: EnvironmentStateService,
        attack_graph_service: AttackGraphService,
    ) -> list[Event]:
        events = []

        if self.skip_if_already_executed:
            if attack_graph_service.already_executed_attack_path(self.attack_path):
                return []

        if len(self.attack_path.attack_host.agents) == 0:
            log_event(
                "LATERAL MOVE",
                f"Agent {self.attack_path.attack_host} has no agents to attack {self.attack_path.target_host}",
            )
            return []

        attack_agent = self.attack_path.attack_host.agents[0]
        prior_agents = low_level_action_orchestrator.get_trusted_agents()

        log_event(
            "LATERAL MOVE",
            f"Agent {attack_agent.paw} attacking {self.attack_path.target_host.ip_address}",
        )

        # Attack based on port
        if (
            self.attack_path.attack_technique.PortToAttack
            and self.attack_path.target_host.ip_address
        ):
            port_to_attack = self.attack_path.attack_technique.PortToAttack
            service_to_attack = self.attack_path.target_host.open_ports[port_to_attack]
            port_to_attack = str(port_to_attack)
            ip_to_attack = self.attack_path.target_host.ip_address

            # If no credentials, try to exploit a service
            agent_info = f"{attack_agent.paw} ({attack_agent.host} - {attack_agent.host_ip_addrs})"
            log_event(
                "ATTACKING PORT",
                f"Agent {agent_info} is attacking {port_to_attack} with service {service_to_attack}",
            )

            action_to_run = None

            if service_to_attack == "http":
                action_to_run = ExploitStruts(
                    attack_agent,
                    ip_to_attack,
                    port_to_attack,
                    prior_agents,
                )

            elif port_to_attack == "4444":
                action_to_run = NCLateralMove(
                    attack_agent,
                    ip_to_attack,
                    port_to_attack,
                    prior_agents,
                )

            if action_to_run:
                new_events = await low_level_action_orchestrator.run_action(
                    action_to_run
                )
                events += new_events

        # Attack using credential
        if self.attack_path.attack_technique.CredentialToUse:
            log_event(
                "LATERAL MOVE",
                f"Agent {attack_agent.paw} credential attacking {self.attack_path.attack_technique.CredentialToUse}",
            )
            credential = self.attack_path.attack_technique.CredentialToUse
            new_events = await low_level_action_orchestrator.run_action(
                SSHLateralMove(attack_agent, credential.hostname, prior_agents)
            )
            for event in new_events:
                if type(event) is InfectedNewHost:
                    event.credential_used = credential
                events.append(event)

        return events
