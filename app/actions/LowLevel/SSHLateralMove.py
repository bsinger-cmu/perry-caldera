from ..LowLevelAction import LowLevelAction
from plugins.deception.app.helpers.agent_helpers import get_trusted_agents
from plugins.deception.app.models.events import Event, InfectedNewHost

from app.objects.c_agent import Agent
from app.service.knowledge_svc import KnowledgeService
from app.objects.c_operation import Operation
from app.service.planning_svc import PlanningService

from plugins.deception.app.helpers.logging import log_event

import asyncio


class SSHLateralMove(LowLevelAction):
    ability_name = "deception-ssh-copy"

    def __init__(self, agent: Agent, hostname: str, prior_agents: list[Agent]):
        facts = {"host.lateralMove.sshcmd": hostname}
        super().__init__(agent, facts, SSHLateralMove.ability_name)
        self.hostname = hostname
        self.prior_agents = prior_agents

    async def get_result(
        self,
        operation: Operation,
        planner: PlanningService,
        knowledge_svc_handle: KnowledgeService,
    ) -> list[Event]:
        # sleep to allow for the agent to get to the new host
        await asyncio.sleep(5)

        post_agents = get_trusted_agents(operation)

        # Find the agent that was added to the operation
        for post_agent in post_agents:
            # If the agent paw was not in the prior agents, then it was added
            if post_agent.paw not in [
                prior_agent.paw for prior_agent in self.prior_agents
            ]:
                return [InfectedNewHost(self.agent, post_agent)]

        return []
