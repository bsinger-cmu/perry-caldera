from app.service.knowledge_svc import KnowledgeService
from app.objects.c_operation import Operation
from app.service.planning_svc import PlanningService
from app.objects.c_agent import Agent
from app.objects.secondclass.c_fact import Fact

from plugins.deception.app.actions.LowLevelAction import LowLevelAction
from plugins.deception.app.helpers.ability_helpers import run_ability
from plugins.deception.app.helpers.agent_helpers import get_trusted_agents
from plugins.deception.app.services.environment_state_service import (
    EnvironmentStateService,
)


class LowLevelActionOrchestrator:
    def __init__(
        self,
        operation: Operation,
        planner: PlanningService,
        knowledge_svc_handle: KnowledgeService,
        environment_state_service: EnvironmentStateService,
    ):
        self.operation = operation
        self.planner = planner
        self.knowledge_svc_handle = knowledge_svc_handle
        self.environment_state_service = environment_state_service

    async def run_action(self, low_level_action: LowLevelAction):
        # Reset any reset facts
        for fact_trait in low_level_action.reset_facts:
            await self.remove_fact(fact_trait, low_level_action.agent)

        # Add action facts
        action_facts = low_level_action.facts
        for fact_trait, fact_value in action_facts.items():
            await self.add_fact(fact_trait, fact_value, low_level_action.agent)

        # Run the action
        await run_ability(
            self.planner,
            self.operation,
            low_level_action.agent,
            low_level_action.ability_name,
        )

        # Get the results
        return await low_level_action.get_result(
            self.operation,
            self.planner,
            self.knowledge_svc_handle,
        )

    async def add_fact(
        self,
        fact_trait: str,
        fact_value: str,
        agent: Agent,
    ):
        await self.remove_fact(fact_trait, agent)

        scan_addr_fact = Fact(
            trait=fact_trait,
            value=fact_value,
            source=self.operation.id,
            collected_by=[agent.paw],
        )

        await self.knowledge_svc_handle.add_fact(fact=scan_addr_fact)

    async def remove_fact(self, fact_trait: str, agent: Agent):
        facts = await self.knowledge_svc_handle.get_facts(
            criteria=dict(
                trait="host.remote.ip",
                source=self.operation.id,
                collected_by=[agent.paw],
            )
        )
        # Delete relationships
        for fact in facts:
            await self.knowledge_svc_handle.delete_relationship(
                criteria=dict(source=fact)
            )
        # Delete all facts
        await self.knowledge_svc_handle.delete_fact(
            criteria=dict(
                trait=fact_trait,
                source=self.operation.id,
            )
        )

    def get_trusted_agents(self):
        return get_trusted_agents(self.operation)
