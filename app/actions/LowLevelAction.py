from abc import ABC, abstractmethod

from app.objects.c_agent import Agent
from app.service.knowledge_svc import KnowledgeService
from app.objects.c_operation import Operation
from app.service.planning_svc import PlanningService

from plugins.deception.app.models.events import Event


class LowLevelAction(ABC):
    def __init__(
        self,
        agent: Agent,
        facts: dict[str, str],
        ability_name: str,
        reset_facts: list[str] | None = None,
    ):
        self.agent = agent
        self.facts = facts
        self.ability_name = ability_name

        if reset_facts:
            self.reset_facts = reset_facts
        else:
            self.reset_facts = []

    async def get_result(
        self,
        operation: Operation,
        planner: PlanningService,
        knowledge_svc_handle: KnowledgeService,
    ) -> list[Event]:
        return []
