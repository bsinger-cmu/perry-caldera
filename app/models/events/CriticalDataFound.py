from plugins.deception.app.models.events import Event
from plugins.deception.app.models.network import Host


class CriticalDataFound(Event):
    def __init__(self, host: Host, files_paths: list[str]):
        self.host: Host = host
        self.files = files_paths

    def __str__(self):
        return f"CriticalDataFound: {self.host} - {self.files}"
