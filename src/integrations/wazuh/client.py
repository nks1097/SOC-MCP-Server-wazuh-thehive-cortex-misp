import base64
from typing import Dict, Any, List, Optional
from src.core.http_client import AsyncHttpClient
from src.config.settings import settings
from src.utils.logger import logger
from src.core.ssh_client import AsyncSSHClient

class WazuhClient:
    def __init__(self):
        self.base_url = f"https://{settings.WAZUH_HOST}:{settings.WAZUH_API_PORT}"
        self.client = AsyncHttpClient(self.base_url, verify=False)
        self.token = None
        self.ssh_client = AsyncSSHClient(
            host=settings.WAZUH_HOST,
            port=settings.WAZUH_SSH_PORT,
            username=settings.WAZUH_SSH_USER,
            password=settings.WAZUH_SSH_PASS
        )

    async def authenticate(self):
        auth_string = f"{settings.WAZUH_USER}:{settings.WAZUH_PASS}"
        encoded_auth = base64.b64encode(auth_string.encode()).decode()
        headers = {"Authorization": f"Basic {encoded_auth}"}
        
        # Temporary client for auth
        auth_client = AsyncHttpClient(self.base_url, headers=headers, verify=False)
        try:
            response = await auth_client.get("/security/user/authenticate")
            self.token = response.get("data", {}).get("token")
            self.client.headers["Authorization"] = f"Bearer {self.token}"
            logger.info("Wazuh authentication successful")
        finally:
            await auth_client.close()

    async def get_alerts(self, limit: int = 10, rule_level: Optional[int] = None) -> List[Dict[str, Any]]:
        import paramiko
        import json
        
        alerts = []
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(settings.WAZUH_HOST, port=settings.WAZUH_SSH_PORT, username=settings.WAZUH_SSH_USER, password=settings.WAZUH_SSH_PASS)
            
            fetch_count = max(limit * 10, 200) if rule_level is not None else limit
            full_cmd = f"sudo -S grep '^\\{{\\\"' /var/ossec/logs/alerts/alerts.json | tail -n {fetch_count}"
                
            stdin, stdout, stderr = ssh.exec_command(full_cmd)
            stdin.write(settings.WAZUH_SSH_PASS + '\n')
            stdin.flush()
            output = stdout.read().decode('utf-8').strip().split('\n')
            logger.debug(f"SSH fetched {len(output)} lines from alerts.json")
            for line in output:
                if line.strip():
                    try:
                        alert_obj = json.loads(line)
                    except Exception as json_e:
                        try:
                            import re
                            fixed_line = re.sub(r'\\(?![/\\bfnrtu"])', r'\\\\', line)
                            alert_obj = json.loads(fixed_line)
                        except Exception:
                            logger.debug(f"Linha de alerta ignorada no parse JSON: {str(json_e)}")
                            continue

                    if rule_level is not None:
                        lvl = int(alert_obj.get("rule", {}).get("level", 0))
                        if lvl >= rule_level:
                            alerts.append(alert_obj)
                    else:
                        alerts.append(alert_obj)
            if rule_level is not None:
                alerts = alerts[-limit:]
        except Exception as e:
            logger.error(f"Error fetching alerts via SSH: {str(e)}")
        finally:
            ssh.close()
            
        return alerts

    async def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        import paramiko
        import json
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(settings.WAZUH_HOST, port=settings.WAZUH_SSH_PORT, username=settings.WAZUH_SSH_USER, password=settings.WAZUH_SSH_PASS)
            
            full_cmd = f"sudo -S grep '\\\"id\\\":\\\"{alert_id}\\\"' /var/ossec/logs/alerts/alerts.json | head -n 1"
            stdin, stdout, stderr = ssh.exec_command(full_cmd)
            stdin.write(settings.WAZUH_SSH_PASS + '\\n')
            stdin.flush()
            
            output = stdout.read().decode('utf-8').strip()
            if output:
                return json.loads(output)
        except Exception as e:
            logger.error(f"Error fetching alert by ID via SSH: {str(e)}")
        finally:
            ssh.close()
        return None

    async def search_alerts(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        import paramiko
        import json
        alerts = []
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(settings.WAZUH_HOST, port=settings.WAZUH_SSH_PORT, username=settings.WAZUH_SSH_USER, password=settings.WAZUH_SSH_PASS)
            
            full_cmd = f"sudo -S grep -i '{query}' /var/ossec/logs/alerts/alerts.json | grep '^\\{{\\\"' | tail -n {limit}"
            stdin, stdout, stderr = ssh.exec_command(full_cmd)
            stdin.write(settings.WAZUH_SSH_PASS + '\\n')
            stdin.flush()
            
            output = stdout.read().decode('utf-8').strip().split('\n')
            for line in output:
                if line.strip():
                    try:
                        alerts.append(json.loads(line))
                    except Exception:
                        pass
        except Exception as e:
            logger.error(f"Error searching alerts via SSH: {str(e)}")
        finally:
            ssh.close()
        return alerts

    async def get_agents(self) -> List[Dict[str, Any]]:
        if not self.token:
            await self.authenticate()
        response = await self.client.get("/agents")
        return response.get("data", {}).get("affected_items", [])
        
    async def get_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        if not self.token:
            await self.authenticate()
        response = await self.client.get(f"/agents/{agent_id}")
        items = response.get("data", {}).get("affected_items", [])
        return items[0] if items else None

    async def run_active_response(self, agent_id: str, command: str, arguments: List[str]):
        if not self.token:
            await self.authenticate()
        payload = {
            "command": command,
            "arguments": arguments,
            "custom": False
        }
        response = await self.client.put(f"/active-response?agents_list={agent_id}", json=payload)
        return response

    async def close(self):
        await self.client.close()
        await self.ssh_client.close()
