from ..LowLevelAction import LowLevelAction

from app.service.knowledge_svc import KnowledgeService
from app.objects.c_operation import Operation
from app.service.planning_svc import PlanningService
from app.objects.c_agent import Agent

from plugins.deception.app.models.network import Host
from plugins.deception.app.models.events import SSHCredentialFound, Event

from plugins.deception.app.helpers.logging import log_event


class FindSSHConfig(LowLevelAction):
    ability_name = "deception-parse-sshconfig"

    def __init__(self, agent: Agent, host: Host):
        reset_facts = ["remote.ssh.hostname", "remote.ssh.hostinfo"]
        super().__init__(agent, {}, FindSSHConfig.ability_name, reset_facts=reset_facts)
        self.host = host

    async def get_result(
        self,
        operation: Operation,
        planner: PlanningService,
        knowledge_svc_handle: KnowledgeService,
    ) -> list[Event]:
        # See if fact has a new relationship
        ssh_cred_facts = await knowledge_svc_handle.get_facts(
            criteria=dict(
                trait="remote.ssh.hostname",
                source=operation.id,
                collected_by=[self.agent.paw],
            )
        )

        events = []
        for ssh_cred in ssh_cred_facts:
            # Get relationships
            relationship = await knowledge_svc_handle.get_relationships(
                criteria=dict(source=ssh_cred)
            )

            if relationship is None or len(relationship) != 1:
                log_event("FindSSHConfig", "Error: Relationship not found")
                continue

            hostname = ssh_cred.value

            # Host info is string formatted as "username@hostname:port"
            hostinfo = relationship[0].target.value
            ssh_cred = hostinfo.split(":")
            port = ssh_cred[1]
            ssh_cred = ssh_cred[0]
            ssh_cred = ssh_cred.split("@")
            events.append(
                SSHCredentialFound(self.host, hostname, ssh_cred[0], ssh_cred[1], port)
            )

        return events
