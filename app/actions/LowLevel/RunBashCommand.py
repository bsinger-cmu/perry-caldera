from ..LowLevelAction import LowLevelAction

from app.objects.c_agent import Agent
from app.objects.secondclass.c_fact import Fact
from app.service.knowledge_svc import KnowledgeService
from app.objects.c_operation import Operation
from app.service.planning_svc import PlanningService

from plugins.deception.app.models.events import Event, BashOutputEvent


class RunBashCommand(LowLevelAction):
    ability_name = "deception-runbashcommand"

    def __init__(self, agent: Agent, command: str):
        facts = {"host.command.input": command}
        self.command = command
        super().__init__(agent, facts, RunBashCommand.ability_name)

    async def get_result(
        self,
        operation: Operation,
        planner: PlanningService,
        knowledge_svc_handle: KnowledgeService,
    ) -> list[Event]:
        # See if fact has a new relationship
        run_command_facts = await knowledge_svc_handle.get_facts(
            criteria=dict(
                trait="host.command.output",
                source=operation.id,
                collected_by=[self.agent.paw],
            )
        )

        results = []
        for fact in run_command_facts:
            results.append(fact.value)

        return [BashOutputEvent(self.agent, "".join(results))]
