from pydantic import BaseModel
from enum import Enum
from typing import Optional


# Enum of environments
class Environment(Enum):
    EQUIFAX_SMALL = "EquifaxSmall"
    EQUIFAX_MEDIUM = "EquifaxMedium"
    EQUIFAX_LARGE = "EquifaxLarge"
    ICS = "ICSEnvironment"
    RING = "RingEnvironment"
    ENTERPRISE_A = "EnterpriseA"
    ENTERPRISE_B = "EnterpriseB"


class Abstraction(Enum):
    HIGH_LEVEL = "high"
    LOW_LEVEL = "low"
    NO_SERVICES = "no_services"
    NO_ABSTRACTION = "none"


def convert_to_environment(env: str) -> Environment:
    try:
        return Environment(env)
    except ValueError:
        raise ValueError(f"'{env}' is not a valid environment")


def convert_to_abstraction_level(level: str) -> Abstraction:
    try:
        return Abstraction(level)
    except ValueError:
        raise ValueError(f"'{level}' is not a valid level of abstraction")


class AttackerConfig(BaseModel):
    name: str
    strategy: str
    environment: str
    abstraction: Optional[Abstraction] = Abstraction.HIGH_LEVEL
