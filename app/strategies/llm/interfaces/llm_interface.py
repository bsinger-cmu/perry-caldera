import os

from abc import ABC, abstractmethod

from plugins.deception.app.data.attacker_config import Abstraction

from plugins.deception.app.strategies.llm.llm_response import (
    LLMResponse,
    LLMResponseType,
)

from plugins.deception.app.services.environment_state_service import (
    EnvironmentStateService,
)


def extract_code_blocks(text):
    code_blocks = []
    lines = text.split("\n")
    in_code_block = False
    current_block = []

    for line in lines:
        if line.strip().startswith("```"):
            if in_code_block:
                code_blocks.append("\n".join(current_block))
                current_block = []
                in_code_block = False
            else:
                in_code_block = True
        elif in_code_block:
            current_block.append(line)

    return code_blocks


# String contains <query> and </query> tags
# Extract the query between the tags
def extract_query(text):
    start = text.find("<query>")
    end = text.find("</query>")
    return text[start + len("<query>") : end]


def extract_action(text):
    start = text.find("<action>")
    end = text.find("</action>")
    return text[start + len("<action>") : end]


def extract_med_action(text):
    start = text.find("<mediumAction>")
    end = text.find("</mediumAction>")
    return text[start + len("<mediumAction>") : end]


def extract_command(text):
    start = text.find("<bash>")
    end = text.find("</bash>")
    return text[start + len("<bash>") : end]


class LLMInterface(ABC):
    def __init__(
        self, logger, environment_state_service: EnvironmentStateService, config
    ):
        self.logger = logger

        # Path of current file
        current_file = os.path.abspath(__file__)
        path = os.path.dirname(current_file)
        pre_prompt_path = f"{path}/preprompts"
        pre_prompt = ""

        # Read pre-prompt file
        if config.abstraction == Abstraction.NO_ABSTRACTION:
            with open(f"{pre_prompt_path}/bash/pre_prompt.txt", "r") as file:
                pre_prompt += file.read()
            with open(f"{pre_prompt_path}/bash/final_prompt.txt", "r") as file:
                final_prompt = file.read()
        elif config.abstraction == Abstraction.LOW_LEVEL:
            with open(
                f"{pre_prompt_path}/low-level-actions/pre_prompt.txt", "r"
            ) as file:
                pre_prompt += file.read()
            with open(f"{pre_prompt_path}/low-level-actions/codebase.txt", "r") as file:
                pre_prompt += file.read()
            with open(
                f"{pre_prompt_path}/low-level-actions/final_prompt.txt", "r"
            ) as file:
                final_prompt = file.read()
        elif config.abstraction == Abstraction.HIGH_LEVEL:
            with open(f"{pre_prompt_path}/perry/pre_prompt.txt", "r") as file:
                pre_prompt += file.read()
            with open(f"{pre_prompt_path}/perry/codebase.txt", "r") as file:
                pre_prompt += file.read()
            with open(f"{pre_prompt_path}/perry/final_prompt.txt", "r") as file:
                final_prompt = file.read()
        elif config.abstraction == Abstraction.NO_SERVICES:
            with open(f"{pre_prompt_path}/no-services/pre_prompt.txt", "r") as file:
                pre_prompt += file.read()
            with open(f"{pre_prompt_path}/no-services/codebase.txt", "r") as file:
                pre_prompt += file.read()
            with open(f"{pre_prompt_path}/no-services/final_prompt.txt", "r") as file:
                final_prompt = file.read()
        else:
            raise ValueError("Invalid abstraction")

        # Initial environment state
        initial_env_state = (
            "The following is the initial known information about the environment:\n"
        )
        initial_env_state += str(environment_state_service)

        # Merge the pre-prompt, code base, and final prompt
        self.pre_prompt = pre_prompt + initial_env_state + final_prompt

    def get_llm_action(self, perry_response: str | None = None):
        llm_response = self.get_response(perry_response)

        if "<finished>" in llm_response:
            return LLMResponse(LLMResponseType.FINISHED, llm_response)

        # Check for code blocks and print them separately
        if "<query>" in llm_response:
            query = extract_query(llm_response)
            return LLMResponse(LLMResponseType.QUERY, query)

        if "<action>" in llm_response:
            action = extract_action(llm_response)
            return LLMResponse(LLMResponseType.ACTION, action)

        if "<bash>" in llm_response:
            command = extract_command(llm_response)
            return LLMResponse(LLMResponseType.BASH, command)

        if "<mediumAction>" in llm_response:
            medium_action = extract_med_action(llm_response)
            return LLMResponse(LLMResponseType.MEDIUM_ACTION, medium_action)

        return None

    @abstractmethod
    def get_response(self, perry_response: str | None = None) -> str:
        pass
