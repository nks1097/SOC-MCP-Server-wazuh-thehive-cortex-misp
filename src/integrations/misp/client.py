from typing import Dict, Any, List
from src.core.http_client import AsyncHttpClient
from src.config.settings import settings
from src.utils.logger import logger

class MISPClient:
    def __init__(self):
        self.headers = {
            "Authorization": settings.MISP_API_KEY,
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        self.client = AsyncHttpClient(settings.MISP_URL, headers=self.headers, verify=settings.MISP_VERIFY_SSL)

    async def search_attributes(self, value: str) -> List[Dict[str, Any]]:
        payload = {
            "returnFormat": "json",
            "value": value
        }
        try:
            response = await self.client.post("/attributes/restSearch", json=payload)
            # MISP response structure: {"response": {"Attribute": [...]}}
            return response.get("response", {}).get("Attribute", [])
        except Exception as e:
            logger.error(f"Failed to search MISP for {value}: {e}")
            return []

    async def add_event(self, info: str, distribution: int = 0, threat_level_id: int = 2, analysis: int = 0) -> Dict[str, Any]:
        payload = {
            "Event": {
                "info": info,
                "distribution": distribution,
                "threat_level_id": threat_level_id,
                "analysis": analysis
            }
        }
        response = await self.client.post("/events/add", json=payload)
        logger.info(f"Added MISP event: {info}")
        return response

    async def add_attribute(self, event_id: str, type: str, value: str, category: str) -> Dict[str, Any]:
        payload = {
            "event_id": event_id,
            "type": type,
            "value": value,
            "category": category
        }
        response = await self.client.post(f"/attributes/add/{event_id}", json=payload)
        return response

    async def close(self):
        await self.client.close()
