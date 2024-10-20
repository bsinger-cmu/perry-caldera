from collections import defaultdict
import os
import random

from app.utility.base_service import BaseService
from app.objects.c_operation import Operation
from app.service.planning_svc import PlanningService
from app.service.knowledge_svc import KnowledgeService
from app.objects.c_agent import Agent

from .helpers.logging import get_logger, setup_logger_for_operation, log_event
from .helpers.agent_helpers import find_attacker_agents

from .actions.HighLevel import (
    DiscoverHostInformation,
    LateralMoveToHost,
    AttackPathLateralMove,
    Scan,
    DirectSSHExfiltrate,
)
from .actions.Information import Host, Subnet, Network, AttackPath
from .actions.Information.KnowledgeBase import KnowledgeBase
from .actions.Events import InfectedNewHost

from enum import Enum

plugin_logger = get_logger()


class AgentState(Enum):
    FIND_HOST_INFORMATION = 0
    SCAN = 1
    LATERAL_MOVE = 2
    FINISHED = 3


class RandomState(Enum):
    InitialAccess = 0
    RandomSpread = 1
    Finished = 2


class LogicalPlanner:
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
        )

        self.trusted_agents: list[Agent] = []
        self.initial_agents: list[Agent] = []
        self.attacker_agent: Agent
        self.state = RandomState.InitialAccess
        # agent paw -> state
        self.agent_states: dict[str, AgentState] = {}
        self.agent_attack_paths: dict[str, list[AttackPath]] = {}
        self.attack_path_queue: list[AttackPath] = []

        # Setup logger
        setup_logger_for_operation(self.operation.id)
        plugin_logger.info(f"* NEW OPERATION STARTED at {self.operation.start}")

        # Initial network assumptions
        self.attackerSubnet = Subnet("192.168.202.0/24", attacker_subnet=True)
        network = Network(
            [
                Subnet("192.168.200.0/24"),
                self.attackerSubnet,
            ]
        )
        self.knowledge_base = KnowledgeBase(
            network, self.knowledge_svc_handle, operation
        )

        # Setup actions
        self.scanAction = Scan(
            self.operation, self.planning_svc, self.knowledge_svc_handle
        )
        self.discoverInfoAction = DiscoverHostInformation(
            self.operation, self.planning_svc, self.knowledge_svc_handle
        )
        self.infectHostAction = LateralMoveToHost(
            self.operation, self.planning_svc, self.knowledge_svc_handle
        )
        self.attackPathInfect = AttackPathLateralMove(
            self.operation, self.planning_svc, self.knowledge_svc_handle
        )
        self.directSSHExfiltration = DirectSSHExfiltrate(
            self.operation, self.planning_svc, self.knowledge_svc_handle
        )

        # States
        self.state_machine = ["main"]
        # Agents go from try to read flag -> scan -> randomly laterally move -> finished
        self.agent_states = {}

        self.next_bucket = "main"

    def update_trusted_agents(self):
        self.trusted_agents = list(
            filter(lambda agent: agent.trusted, self.operation.agents)
        )

    async def initialize(self):
        attacker_agents = await find_attacker_agents(self.operation)
        if attacker_agents is None:
            log_event("Initialization", "ERROR agent not found")
            self.state = RandomState.Finished
            return
        else:
            self.initial_agents = attacker_agents
            for agent in self.initial_agents:
                self.knowledge_base.add_infected_host(agent)

        if len(self.attackerSubnet.hosts) != 0:
            self.attacker_agent = self.attackerSubnet.hosts[0].agents[0]
        else:
            self.attacker_agent = self.initial_agents[0]

    async def execute(self):
        log_event("EXECUTE", "Executing logical planner")
        self.update_trusted_agents()
        await self.initialize()
        await self.planning_svc.execute_planner(self)

    async def main(self):
        # Check if any new agents were created
        self.update_trusted_agents()
        self.update_agent_states()
        self.knowledge_base.update_host_agents(self.trusted_agents)

        if self.state == RandomState.InitialAccess:
            await self.initial_access()
        elif self.state == RandomState.RandomSpread:
            await self.random_spread()
        elif self.state == RandomState.Finished:
            self.stopping_condition_met = True
            self.next_bucket = None
            return

        self.next_bucket = "main"
        return

    def update_agent_states(self):
        for agent in self.trusted_agents:
            if (
                agent.paw not in self.agent_states
                and agent.paw != self.attacker_agent.paw
            ):
                self.agent_states[agent.paw] = AgentState.FIND_HOST_INFORMATION

        # Remove agents that are no longer in operation
        for agent_paw in list(self.agent_states.keys()):
            if agent_paw not in [agent.paw for agent in self.trusted_agents]:
                del self.agent_states[agent_paw]

    async def initial_access(self):
        if self.attacker_agent is None:
            self.stopping_condition_met = True
            self.next_bucket = None
            return

        if len(self.attackerSubnet.hosts) != 0:
            # Use attacker host to scan external network
            attacker_host = self.attackerSubnet.hosts[0]
            self.attacker_agent = attacker_host.agents[0]

            events = await self.scanAction.run(
                self.attacker_agent, self.knowledge_base.network.get_all_subnets()
            )
            await self.knowledge_base.parse_events(events)
        else:
            # Use initial host to scan current subnet
            initial_agent = self.initial_agents[0]
            attacker_host = self.knowledge_base.network.find_host_by_agent(
                initial_agent
            )

            cur_subnet = self.knowledge_base.network.find_subnet_by_host(attacker_host)
            if cur_subnet is None:
                log_event("Initialization", "Error, subnet not found")
                self.stopping_condition_met = True
                self.next_bucket = None
                return
            else:
                events = await self.scanAction.run(self.attacker_agent, [cur_subnet])
                await self.knowledge_base.parse_events(events)

        # Add initial paths to queue
        new_paths = self.knowledge_base.network.get_possible_targets_from_host(
            attacker_host
        )
        random.shuffle(new_paths)
        self.attack_path_queue.extend(new_paths)

        self.state = RandomState.RandomSpread

    async def random_spread(self):
        if self.all_agents_finished() and len(self.attack_path_queue) == 0:
            self.state = RandomState.Finished
            return

        for agent_paw, agent_state in self.agent_states.items():
            agent = self.get_agent_by_paw(agent_paw)
            if agent is None:
                continue

        # Execute last attack path in queue
        if len(self.attack_path_queue) > 0:
            attack_path = self.attack_path_queue.pop(0)
            if not self.knowledge_base.already_executed_attack_path(attack_path):
                events = await self.attackPathInfect.run(attack_path)
                self.knowledge_base.executed_attack_path(attack_path)
                await self.knowledge_base.parse_events(events)

        for agent_paw, agent_state in self.agent_states.items():
            agent = self.get_agent_by_paw(agent_paw)
            if agent is None:
                continue

            if agent_state == AgentState.FIND_HOST_INFORMATION:
                host = self.knowledge_base.network.find_host_by_agent(agent)
                if host is None:
                    continue

                # New host created: 1) find information, 2) scan, 3) add attack paths to queue
                # Find information
                events = await self.discoverInfoAction.run(agent, host)
                await self.knowledge_base.parse_events(events)

                events = await self.directSSHExfiltration.run(
                    self.attacker_agent, host, self.knowledge_base.network
                )
                await self.knowledge_base.parse_events(events)

                # Add attack paths to queue
                new_paths = self.knowledge_base.network.get_possible_targets_from_host(
                    host
                )
                random.shuffle(new_paths)
                # Push new paths to queue
                self.attack_path_queue = new_paths + self.attack_path_queue
                self.agent_states[agent_paw] = AgentState.FINISHED

        return

    def get_agent_by_paw(self, paw: str):
        for agent in self.trusted_agents:
            if agent.paw == paw:
                return agent

        return None

    def all_agents_finished(self):
        for agent_paw, agent_state in self.agent_states.items():
            if agent_state != AgentState.FINISHED:
                return False

        return True
