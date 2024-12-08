from plugins.deception.app.actions.LowLevelAction import LowLevelAction

from app.objects.c_agent import Agent
from app.service.knowledge_svc import KnowledgeService
from app.objects.c_operation import Operation
from app.service.planning_svc import PlanningService

from plugins.deception.app.models.events import Event, WriteableSudoers


class CheckSudoersPermissions(LowLevelAction):
    ability_name = "deception-runbashcommand"

    def __init__(self, agent: Agent):
        command = "ls -l /etc/sudoers"
        facts = {"host.command.input": command}
        self.command = command

        super().__init__(agent, facts, self.ability_name)

    async def get_result(
        self,
        operation: Operation,
        planner: PlanningService,
        knowledge_svc_handle: KnowledgeService,
        raw_result: dict | None = None,
    ) -> list[Event]:
        if raw_result is None:
            return []

        output = raw_result["stdout"]
        permissions = output.split(" ")[0]

        if "w" in permissions:
            return [WriteableSudoers(self.agent)]

        return []
