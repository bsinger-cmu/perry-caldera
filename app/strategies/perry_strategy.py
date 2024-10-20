from app.utility.base_service import BaseService
from app.objects.c_operation import Operation
from app.service.planning_svc import PlanningService
from app.service.knowledge_svc import KnowledgeService
from app.objects.c_agent import Agent

from plugins.deception.app.helpers.logging import (
    PerryLogger,
    init_logger,
)

from plugins.deception.app.actions.HighLevel import *
from plugins.deception.app.models.network import *
from plugins.deception.app.models.events import *

from plugins.deception.app.services import (
    EnvironmentStateService,
    AttackGraphService,
    LowLevelActionOrchestrator,
    HighLevelActionOrchestrator,
)

from enum import Enum
from abc import ABC, abstractmethod


class EquifaxAttackerState(Enum):
    InitialAccess = 0
    CredExfiltrate = 1
    Finished = 2


class PerryStrategy(ABC):
    def __init__(
        self,
        operation: Operation,
        planning_svc: PlanningService,
        stopping_conditions=(),
    ):
        self.operation = operation
        self.planning_svc = planning_svc
        self.stopping_conditions = stopping_conditions
        self.stopping_condition_met = False
        self.knowledge_svc_handle: KnowledgeService = BaseService.get_service(
            "knowledge_svc"
        )  # type: ignore

        self.trusted_agents: list[Agent] = []
        self.initial_hosts: list[Host] = []
        self.state = EquifaxAttackerState.InitialAccess
        self.new_initial_access_agent: Agent | None = None
        self.new_initial_access_host: Host | None = None
        self.external_subnet = None

        # Setup logging
        self.log_creator = PerryLogger()
        self.perry_logger = self.log_creator.setup_logger("perry")
        self.perry_logger.info("Perry logger initialized")
        init_logger(self.log_creator.logger_dir_path)

        # Services
        self.environment_state_service: EnvironmentStateService = (
            EnvironmentStateService(self.knowledge_svc_handle, operation)
        )
        self.attack_graph_service: AttackGraphService = AttackGraphService(
            self.environment_state_service
        )
        # Orchestrators
        self.low_level_action_orchestrator = LowLevelActionOrchestrator(
            self.operation,
            self.planning_svc,
            self.knowledge_svc_handle,
            self.environment_state_service,
        )
        self.high_level_action_orchestrator = HighLevelActionOrchestrator(
            self.environment_state_service,
            self.attack_graph_service,
            self.low_level_action_orchestrator,
        )

        # States
        self.state_machine = ["main"]
        # Agents go from try to read flag -> scan -> randomly laterally move -> finished
        self.agent_states = {}

        self.next_bucket = "main"

    async def initialize(self):
        self.update_trusted_agents()
        if len(self.trusted_agents) == 0:
            self.perry_logger.error("No trusted agents found")
            raise Exception("No trusted agents found")

        self.environment_state_service.update_host_agents(self.trusted_agents)
        self.initial_hosts = self.environment_state_service.get_hosts_with_agents()

    def update_trusted_agents(self):
        self.trusted_agents = list(
            filter(lambda agent: agent.trusted, self.operation.agents)
        )

    async def execute(self):
        self.perry_logger.info("Executing strategy...")
        self.update_trusted_agents()

        await self.initialize()
        await self.planning_svc.execute_planner(self)

    async def main(self):
        # Check if any new agents were created
        self.update_trusted_agents()
        self.environment_state_service.update_host_agents(self.trusted_agents)

        finished = await self.step()

        if finished:
            self.state = EquifaxAttackerState.Finished
            self.stopping_condition_met = True
            self.next_bucket = None
            return

        self.next_bucket = "main"

    @abstractmethod
    async def step(self) -> bool:
        pass
