import asyncio
from typing import Dict, Any, List
from src.core.http_client import AsyncHttpClient
from src.config.settings import settings
from src.utils.logger import logger

class CortexClient:
    def __init__(self):
        self.headers = {
            "Authorization": f"Bearer {settings.CORTEX_API_KEY}"
        }
        self.client = AsyncHttpClient(settings.CORTEX_URL, headers=self.headers, verify=False)

    async def list_analyzers(self) -> List[Dict[str, Any]]:
        response = await self.client.get("/api/analyzer")
        return response

    async def run_analyzer(self, analyzer_id: str, data_type: str, data: str, tlp: int = 2) -> Dict[str, Any]:
        payload = {
            "data": data,
            "dataType": data_type,
            "tlp": tlp
        }
        response = await self.client.post(f"/api/analyzer/{analyzer_id}/run", json=payload)
        logger.info(f"Started analyzer {analyzer_id} for {data}")
        return response

    async def get_job_report(self, job_id: str) -> Dict[str, Any]:
        response = await self.client.get(f"/api/job/{job_id}/report")
        return response
        
    async def wait_for_job(self, job_id: str, max_retries: int = 30, delay: int = 2) -> Dict[str, Any]:
        for i in range(max_retries):
            job_info = await self.client.get(f"/api/job/{job_id}")
            status = job_info.get("status")
            if status == "Success":
                return await self.get_job_report(job_id)
            elif status == "Failure":
                logger.error(f"Cortex job {job_id} failed")
                return {"error": "Job failed", "details": job_info}
            await asyncio.sleep(delay)
        
        return {"error": "Timeout waiting for job completion"}

    async def close(self):
        await self.client.close()
