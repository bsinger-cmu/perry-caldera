from ..HighLevelAction import HighLevelAction
from ..LowLevel.ScanHost import ScanHost
from ..LowLevel.ScanNetwork import ScanNetwork

from plugins.deception.app.models.events import HostsDiscovered, Event
from plugins.deception.app.models.network import Subnet, Host
from plugins.deception.app.services import (
    LowLevelActionOrchestrator,
    EnvironmentStateService,
    AttackGraphService,
)

from collections import defaultdict

from plugins.deception.app.helpers.logging import log_event


class Scan(HighLevelAction):
    def __init__(self, scan_host: Host, subnets_to_scan: list[Subnet]):
        self.scan_host = scan_host
        self.subnets_to_scan = subnets_to_scan

    async def run(
        self,
        low_level_action_orchestrator: LowLevelActionOrchestrator,
        environment_state_service: EnvironmentStateService,
        attack_graph_service: AttackGraphService,
    ) -> list[Event]:
        events = []
        scan_agent = self.scan_host.get_agent()
        if not scan_agent:
            log_event("Scan", f"No agent found for host {self.scan_host}")
            return events

        # Scan the subnets specified by the user
        collected_ips = []
        for subnet in self.subnets_to_scan:
            log_event("Scan", f"Scanning subnet: {subnet}")
            new_events = await low_level_action_orchestrator.run_action(
                ScanNetwork(scan_agent, subnet.ip_mask)
            )

            for event in new_events:
                if isinstance(event, HostsDiscovered):
                    collected_ips.extend(event.host_ips)
            events += new_events

        collected_ips = _group_ips(collected_ips)

        for ip_to_scan in collected_ips:
            log_event("Scan", f"Scanning host: {ip_to_scan}")
            new_events = await low_level_action_orchestrator.run_action(
                ScanHost(scan_agent, ip_to_scan)
            )
            events += new_events

        return events


def _group_ips(ips):
    # Create a dictionary where the keys are subnets and the values are lists of hosts
    subnet_to_ips = defaultdict(list)

    for ip in ips:
        # Split the IP into subnet and host
        subnet, host = ip.rsplit(".", 1)
        # Append the host to the list of hosts for this subnet
        subnet_to_ips[subnet].append(host)

    # Create a list to hold the final IP addresses
    grouped_ips = []

    for subnet, hosts in subnet_to_ips.items():
        # Join the hosts with commas and append the subnet
        grouped_ips.append(f"{subnet}.{','.join(hosts)}")

    return grouped_ips
