from pydantic import BaseModel
from enum import Enum


# Enum of environments
class Environment(Enum):
    EQUIFAX_LARGE = "EquifaxLarge"
    ICS = "ICSEnvironment"
    RING = "RingEnvironment"


def convert_to_environment(env: str) -> Environment:
    try:
        return Environment(env)
    except ValueError:
        raise ValueError(f"'{env}' is not a valid environment")


class AttackerConfig(BaseModel):
    name: str
    strategy: str
    environment: str
