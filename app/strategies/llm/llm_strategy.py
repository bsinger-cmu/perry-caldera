from app.objects.c_operation import Operation
from app.service.planning_svc import PlanningService
import traceback

from plugins.deception.app.actions.HighLevelAction import HighLevelAction
from plugins.deception.app.actions.LowLevelAction import LowLevelAction
from plugins.deception.app.actions.HighLevel import *
from plugins.deception.app.actions.LowLevel import *
from plugins.deception.app.models.network import *
from plugins.deception.app.models.events import *
from plugins.deception.app.strategies.perry_strategy import PerryStrategy

from plugins.deception.app.strategies.llm.llm_response import (
    LLMResponseType,
)
from plugins.deception.app.strategies.llm.interfaces.sonnet3_interface import (
    LLMInterface,
)

from abc import ABC, abstractmethod

import anthropic

client = anthropic.Anthropic()


class LLMStrategy(PerryStrategy, ABC):
    def __init__(
        self,
        operation: Operation,
        planning_svc: PlanningService,
        stopping_conditions=(),
    ):
        super().__init__(operation, planning_svc, stopping_conditions)

        # Init claude logger
        self.llm_logger = self.log_creator.setup_logger("llm")
        self.llm_logger.info("LLM logger initialized")

        # Initial network assumptions
        self.llm_interface = self.create_llm_interface()

        self.cur_step = 0
        self.total_steps = 50
        self.last_response = None

    @abstractmethod
    def create_llm_interface(self) -> LLMInterface:
        pass

    async def step(self) -> bool:
        # Check if any new agents were created
        self.update_trusted_agents()
        self.environment_state_service.update_host_agents(self.trusted_agents)

        finished = await self.llm_request()

        if self.cur_step > self.total_steps or finished:
            return True
        else:
            self.cur_step += 1
            return False

    async def llm_request(self) -> bool:
        try:
            llm_action = self.llm_interface.get_llm_action(self.last_response)
        except Exception as e:
            self.llm_logger.error(f"Error getting LLM action: {e}")
            return False

        new_perr_reponse = ""
        if llm_action is None:
            new_perr_reponse = "Perry did not find a <finished> <query>, <bash> or <action> tag. Please try again and include a tag."
            self.last_response = new_perr_reponse
            return False

        if llm_action.response_type == LLMResponseType.FINISHED:
            return True

        try:
            if llm_action.response_type == LLMResponseType.QUERY:
                query = llm_action.response
                self.perry_logger.info(f"Claude query: \n{query}")
                object_info = "The query result is: \n"
                objects = await dynamic_query_execution(
                    self.environment_state_service, self.attack_graph_service, query
                )
                for obj in objects:
                    # Check if the object is Host
                    object_info += str(obj) + "\n"

                self.perry_logger.info(f"Query response: \n{object_info}")
                self.last_response = object_info
                return False

            if llm_action.response_type == LLMResponseType.ACTION:
                action = llm_action.response
                self.perry_logger.info(f"Claude action: \n{action}")
                action_obj = await dynamic_action_execution(
                    self.environment_state_service, self.attack_graph_service, action
                )

                event_info = "The actions had the following events: \n"
                if type(action_obj) is not list:
                    action_obj = [action_obj]

                for action in action_obj:
                    events = []
                    if isinstance(action, HighLevelAction):
                        events = await self.high_level_action_orchestrator.run_action(
                            action
                        )
                    elif isinstance(action, LowLevelAction):
                        events = await self.low_level_action_orchestrator.run_action(
                            action
                        )

                    for event in events:
                        event_info += str(event) + "\n"

                self.perry_logger.info(f"Action response: \n{event_info}")
                self.last_response = event_info
                return False

            if llm_action.response_type == LLMResponseType.BASH:
                command = llm_action.response
                self.perry_logger.info(f"Bash command: \n{command}")
                object_info = "The result is: \n"
                attacker_host = (
                    self.environment_state_service.network.find_host_by_hostname(
                        "attacker"
                    )
                )
                if attacker_host == None:
                    raise Exception("Attacker agent doesn't exist.")
                attacker_agent = attacker_host.agents[0]
                lowlevelbashcommand = RunBashCommand(attacker_agent, command)
                results = await self.low_level_action_orchestrator.run_action(
                    lowlevelbashcommand
                )
                for result in results:
                    if isinstance(result, BashOutputEvent):
                        object_info += result.bash_output
                        break

                self.perry_logger.info(f"Command response: \n{object_info}")
                self.last_response = object_info
                return False

        except Exception as e:
            self.last_response = f"Error executing bash, query or action: {e} \n"
            self.last_response += traceback.format_exc()

            self.perry_logger.error(
                f"Error executing bash, query or action: \n{self.last_response}"
            )
            return False

        return False


async def dynamic_query_execution(
    environment_state_service, attack_graph_service, code
):
    exec_globals = {}
    exec_locals = {}
    exec(code, exec_globals, exec_locals)

    # Retrieve the defined async function from exec_locals
    query_function = exec_locals["query"]

    # Call the dynamically defined async function with await
    result = await query_function(environment_state_service, attack_graph_service)

    return result


async def dynamic_action_execution(
    environment_state_service, attack_graph_service, code
):
    exec_globals = globals()
    exec_locals = {}
    exec(code, exec_globals, exec_locals)

    # Retrieve the defined async function from exec_locals
    action_function = exec_locals["action"]

    # Call the dynamically defined async function with await
    result = await action_function(environment_state_service, attack_graph_service)

    return result


# async def action(
#     environment_state_service: EnvironmentStateService,
#     attack_graph_service: AttackGraphService,
# ):
#     # Do something
#     subnets = environment_state_service.network.get_all_subnets()
#     attacker_host = environment_state_service.network.find_host_by_hostname("attacker")
#     return Scan(attacker_host, subnets)


# async def query(
#     environment_state_service,
#     attack_graph_service,
# ):
#     return environment_state_service.network.get_all_hosts()
