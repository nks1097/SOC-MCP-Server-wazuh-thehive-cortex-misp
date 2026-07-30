import json
from typing import List, Dict, Any
from src.core.ssh_client import AsyncSSHClient
from src.config.settings import settings
from src.utils.logger import logger

class DockerSSHClient:
    def __init__(self):
        self.ssh = AsyncSSHClient(
            host=settings.DOCKER_HOST_SSH_IP,
            port=settings.DOCKER_HOST_SSH_PORT,
            username=settings.DOCKER_HOST_SSH_USER,
            password=settings.DOCKER_HOST_SSH_PASS
        )

    async def list_containers(self) -> List[Dict[str, Any]]:
        # Using docker format json to parse easily
        command = "docker ps -a --format '{{json .}}'"
        exit_status, stdout, stderr = await self.ssh.execute(command)
        
        if exit_status != 0:
            logger.error(f"Failed to list containers: {stderr}")
            raise Exception(f"Docker ps failed: {stderr}")
            
        containers = []
        for line in stdout.strip().split('\n'):
            if line:
                try:
                    containers.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return containers

    async def get_logs(self, container_id_or_name: str, tail: int = 100) -> str:
        command = f"docker logs --tail {tail} {container_id_or_name}"
        exit_status, stdout, stderr = await self.ssh.execute(command)
        # docker logs prints to both stdout and stderr
        return stdout + stderr

    async def restart_container(self, container_id_or_name: str) -> bool:
        command = f"docker restart {container_id_or_name}"
        exit_status, stdout, stderr = await self.ssh.execute(command)
        if exit_status == 0:
            logger.info(f"Restarted container {container_id_or_name}")
            return True
        logger.error(f"Failed to restart container {container_id_or_name}: {stderr}")
        return False

    async def execute_command(self, container_id_or_name: str, cmd: str) -> str:
        command = f"docker exec {container_id_or_name} {cmd}"
        exit_status, stdout, stderr = await self.ssh.execute(command)
        if exit_status == 0:
            return stdout
        raise Exception(f"Docker exec failed: {stderr}")

    async def close(self):
        await self.ssh.close()
