from plugins.deception.app.models.events.Event import Event
from plugins.deception.app.models.network import Host, SSHCredential


class CredentialFound(Event):
    def __init__(self, host: Host):
        self.host = host

    def __str__(self):
        return f"{self.__class__.__name__} on host {self.host}"


class SSHCredentialFound(CredentialFound):
    def __init__(
        self,
        host: Host,
        hostname: str,
        ssh_username: str,
        ssh_host: str,
        port: str,
    ):
        super().__init__(host)
        self.credential = SSHCredential(hostname, ssh_host, ssh_username, port)

    def __str__(self):
        return f"{self.__class__.__name__}: on host {self.host.hostname} with {self.credential}"
