from app.objects.secondclass.c_link import Link
from app.objects.c_agent import Agent
from app.service.planning_svc import PlanningService

import logging

plugin_logger = logging.getLogger("deception-plugin")


async def get_link_by_ability_id(
    planning_svc, operation, agent=None, ability_id=None
) -> Link | None:
    """
    Get a link by ability_id
    :param planning_svc:
    :param operation:
    :param agent:
    :param ability_id:
    :return: Link if found or None
    """
    all_agent_links = await planning_svc.get_links(operation=operation, agent=agent)
    if ability_id:
        for link in all_agent_links:
            if link.ability.ability_id == ability_id:
                return link

    return None


async def run_ability(
    planning_svc: PlanningService, operation, agent: Agent, ability_id, timeout_retry=2
):
    plugin_logger.debug(f"Running ability {ability_id} on {agent.host} ({agent.paw})")

    for _ in range(timeout_retry):
        link_to_run = await get_link_by_ability_id(
            planning_svc, operation, agent=agent, ability_id=ability_id
        )
        if not link_to_run:
            plugin_logger.debug(
                f"Link not found for {ability_id} on {agent.host} ({agent.paw})"
            )
            return

        # Run the link
        link_id = await operation.apply(link_to_run)
        await operation.wait_for_links_completion([link_id])
        # Check status of link
        if link_to_run.status != link_to_run.states["TIMEOUT"]:
            break
