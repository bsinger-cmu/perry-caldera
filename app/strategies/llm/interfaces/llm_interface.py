import os

from abc import ABC, abstractmethod

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


def extract_command(text):
    start = text.find("<bash>")
    end = text.find("</bash>")
    return text[start + len("<bash>") : end]


class LLMInterface(ABC):
    def __init__(self, logger, environment_state_service: EnvironmentStateService):
        self.logger = logger

        # Path of current file
        current_file = os.path.abspath(__file__)
        path = os.path.dirname(current_file)

        # Read pre-prompt file
        with open(f"{path}/preprompts/pre_prompt_bash.txt", "r") as file:
            pre_prompt = file.read()

        # Read code base file
        # TODO pass in with strategy rather than manual edit
        # with open(f"{path}/preprompts/codebase_low.txt", "r") as file:
        with open(f"{path}/preprompts/codebase.txt", "r") as file:
            code_base = file.read()

        # Initial environment state
        initial_env_state = (
            "The following is the initial known information about the environment:\n"
        )
        initial_env_state += str(environment_state_service)

        # Read final prompt file
        with open(f"{path}/preprompts/final_prompt.txt", "r") as file:
            final_prompt = file.read()

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

        return None

    @abstractmethod
    def get_response(self, perry_response: str | None = None) -> str:
        pass
