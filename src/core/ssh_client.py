import asyncssh
from typing import Optional, Tuple
from src.utils.logger import logger

class AsyncSSHClient:
    def __init__(self, host: str, port: int, username: str, password: Optional[str] = None, private_key: Optional[str] = None):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.private_key = private_key
        self.conn = None

    async def connect(self):
        try:
            connect_kwargs = {
                "host": self.host,
                "port": self.port,
                "username": self.username,
                "known_hosts": None # For development, might want to strictly check in prod
            }
            if self.password:
                connect_kwargs["password"] = self.password
            if self.private_key:
                connect_kwargs["client_keys"] = [self.private_key]

            self.conn = await asyncssh.connect(**connect_kwargs)
            logger.info(f"SSH connected to {self.host}:{self.port}")
        except Exception as e:
            logger.error(f"Failed to connect to SSH {self.host}: {e}")
            raise

    async def execute(self, command: str) -> Tuple[int, str, str]:
        if not self.conn:
            await self.connect()
        try:
            logger.debug(f"Executing SSH command on {self.host}: {command}")
            result = await self.conn.run(command)
            return result.exit_status, result.stdout, result.stderr
        except Exception as e:
            logger.error(f"Error executing SSH command on {self.host}: {e}")
            raise

    async def close(self):
        if self.conn:
            self.conn.close()
            await self.conn.wait_closed()
            logger.info(f"SSH connection closed for {self.host}")
