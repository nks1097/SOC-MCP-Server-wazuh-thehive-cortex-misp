from typing import Dict, Any, List, Optional
from src.core.http_client import AsyncHttpClient
from src.config.settings import settings
from src.utils.logger import logger

class TheHiveClient:
    def __init__(self):
        self.headers = {
            "Authorization": f"Bearer {settings.THEHIVE_API_KEY}",
            "Content-Type": "application/json"
        }
        self.client = AsyncHttpClient(settings.THEHIVE_URL, headers=self.headers, verify=False)

    async def list_cases(self, limit: int = 10) -> List[Dict[str, Any]]:
        response = await self.client.get(f"/api/case?sort=-createdAt&limit={limit}")
        logger.info(f"Fetched {len(response)} cases from TheHive")
        return response

    async def create_case(self, title: str, description: str, severity: int = 2, tags: List[str] = None) -> Dict[str, Any]:
        payload = {
            "title": title,
            "description": description,
            "severity": severity,
            "tags": tags or [],
            "tlp": 2,
            "pap": 2
        }
        response = await self.client.post("/api/case", json=payload)
        logger.info(f"Created TheHive case: {response.get('caseId')}")
        return response

    async def add_observable(self, case_id: str, data_type: str, data: str, tags: List[str] = None) -> Dict[str, Any]:
        payload = {
            "dataType": data_type,
            "data": data,
            "tags": tags or [],
            "tlp": 2,
            "ioc": True
        }
        response = await self.client.post(f"/api/case/{case_id}/artifact", json=payload)
        logger.info(f"Added observable to case {case_id}: {data}")
        return response

    async def get_case(self, case_id: str) -> Dict[str, Any]:
        response = await self.client.get(f"/api/case/{case_id}")
        return response

    async def update_case_status(self, case_id: str, status: str, resolution_status: Optional[str] = None) -> Dict[str, Any]:
        """Update case status (e.g., 'Resolved') and optionally resolution status ('FalsePositive', 'TruePositive')."""
        payload = {"status": status}
        if resolution_status:
            payload["resolutionStatus"] = resolution_status
            
        response = await self.client.patch(f"/api/case/{case_id}", json=payload)
        logger.info(f"Updated case {case_id} status to {status}")
        return response

    async def update_case(self, case_id: str, **kwargs) -> Dict[str, Any]:
        """Update case properties (e.g., description, title, severity, tags, status)."""
        response = await self.client.patch(f"/api/case/{case_id}", json=kwargs)
        logger.info(f"Updated case {case_id} with keys: {list(kwargs.keys())}")
        return response

    async def add_case_comment(self, case_id: str, message: str) -> Dict[str, Any]:
        payload = {"message": message}
        response = await self.client.post(f"/api/v1/case/{case_id}/comment", json=payload)
        logger.info(f"Added comment to case {case_id}")
        return response

    async def create_task(self, case_id: str, title: str, description: str = "", status: str = "Waiting") -> Dict[str, Any]:
        payload = {
            "title": title,
            "description": description,
            "status": status,
            "flag": False
        }
        response = await self.client.post(f"/api/case/{case_id}/task", json=payload)
        logger.info(f"Created task '{title}' in case {case_id}")
        return response

    async def add_task_log(self, task_id: str, message: str) -> Dict[str, Any]:
        payload = {"message": message}
        response = await self.client.post(f"/api/case/task/{task_id}/log", json=payload)
        logger.info(f"Added log to task {task_id}")
        return response

    async def delete_case(self, case_id: str) -> Dict[str, Any]:
        """Delete a case from TheHive."""
        response = await self.client.delete(f"/api/case/{case_id}")
        logger.info(f"Deleted case {case_id} from TheHive")
        return response

    async def find_duplicate_case(self, title: str, rule_id: str = None, hours_window: int = 24) -> Optional[Dict[str, Any]]:
        """Find if an identical case was created/updated within the last N hours."""
        try:
            import time
            now_ms = int(time.time() * 1000)
            window_ms = hours_window * 3600 * 1000
            min_time = now_ms - window_ms

            cases = await self.client.get("/api/case?range=0-100&sort=-createdAt")
            for case in cases:
                case_title = case.get("title", "")
                last_time = max(case.get("updatedAt", 0), case.get("createdAt", 0))
                if last_time >= min_time:
                    if case_title == title or (rule_id and f"Regra {rule_id}:" in case_title):
                        logger.info(f"Duplicate case found in TheHive: {case.get('_id')} ({case_title})")
                        return case
            return None
        except Exception as e:
            logger.warning(f"Error checking duplicate cases in TheHive: {e}")
            return None

    async def get_observables(self, case_id: str) -> List[Dict[str, Any]]:
        response = await self.client.get(f"/api/case/{case_id}/artifact")
        return response

    async def close(self):
        await self.client.close()
