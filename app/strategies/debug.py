import random
from app.objects.c_operation import Operation
from app.service.planning_svc import PlanningService
from plugins.deception.app.helpers.logging import (
    get_logger,
    log_event,
)

from plugins.deception.app.strategies.perry_strategy import PerryStrategy

from plugins.deception.app.actions.LowLevel import RunBashCommand, ReadFile
from enum import Enum

plugin_logger = get_logger()


class EquifaxAttackerState(Enum):
    InitialAccess = 0
    CredExfiltrate = 1
    Finished = 2


class LogicalPlanner(PerryStrategy):
    def __init__(
        self,
        operation: Operation,
        planning_svc: PlanningService,
        stopping_conditions=(),
    ):
        super().__init__(operation, planning_svc, stopping_conditions)

        self.state = EquifaxAttackerState.InitialAccess

    async def step(self) -> bool:
        agents = self.environment_state_service.get_agents()
        events = await self.low_level_action_orchestrator.run_action(
            RunBashCommand(agents[0], "ls")
        )
        print("Events: ")
        for event in events:
            print(event.bash_output)  # type: ignore

        return True
