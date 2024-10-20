import json
from aiohttp import web
import os

from app.service.auth_svc import for_all_public_methods, check_authorization


@for_all_public_methods(check_authorization)
class DeceptionAPI:

    def __init__(self, services):
        self.services = services
        self.auth_svc = self.services.get("auth_svc")
        self.data_svc = self.services.get("data_svc")

    async def mirror(self, request):
        """
        This sample endpoint mirrors the request body in its response
        """
        request_body = json.loads(await request.read())
        return web.json_response(request_body)

    async def get_last_log(self, request):
        """
        This endpoint returns the last log entry from the logs table
        """
        logs_dir = "logs/"
        # Get all log directories in the logs directory
        log_dirs = [
            f for f in os.listdir(logs_dir) if os.path.isdir(os.path.join(logs_dir, f))
        ]

        # Sort by creation time, most recent first
        log_dirs.sort(
            key=lambda x: os.path.getctime(os.path.join(logs_dir, x)), reverse=True
        )

        log_data = {}

        # Get llm log
        if len(log_dirs) > 0:
            last_log = log_dirs[0]

            llm_log_path = os.path.join(logs_dir, last_log, "llm.log")
            perry_log_path = os.path.join(logs_dir, last_log, "perry.log")

            # Check if llm log exists
            if os.path.exists(llm_log_path):
                with open(llm_log_path, "r") as llm_log:
                    # Read entire file
                    log_data["llm"] = llm_log.read()
            else:
                log_data["llm"] = None

            # Check if perry log exists
            if os.path.exists(perry_log_path):
                with open(perry_log_path, "r") as perry_log:
                    log_data["perry"] = perry_log.read()
            else:
                log_data["perry"] = None

        # convert to json and return
        return web.json_response(log_data)

    async def post_initial_parameters(self, request):
        """
        This endpoint receives the initial parameters for the deception plugin
        """
        data = await request.json()
        data = json.loads(data)

        # Save parameters
        data_dir = "plugins/deception/app/data/config.json"
        with open(data_dir, "w") as f:
            json.dump(data, f)

        return web.json_response({"status": "success"})
