import httpx
from typing import Any, Dict, Optional
from src.utils.logger import logger

class AsyncHttpClient:
    def __init__(self, base_url: str, headers: Optional[Dict[str, str]] = None, verify: bool = True):
        self.base_url = base_url
        self.headers = headers or {}
        self.verify = verify
        self.client = httpx.AsyncClient(base_url=self.base_url, headers=self.headers, verify=self.verify, timeout=30.0)

    async def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        try:
            response = await self.client.get(endpoint, params=params)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Error GET {endpoint}: {str(e)}")
            raise

    async def post(self, endpoint: str, json: Optional[Dict[str, Any]] = None, data: Any = None) -> Dict[str, Any]:
        try:
            response = await self.client.post(endpoint, json=json, data=data)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Error POST {endpoint}: {str(e)}")
            raise
            
    async def put(self, endpoint: str, json: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        try:
            response = await self.client.put(endpoint, json=json)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Error PUT {endpoint}: {str(e)}")
            raise

    async def patch(self, endpoint: str, json: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        try:
            response = await self.client.patch(endpoint, json=json)
            response.raise_for_status()
            if response.content:
                return response.json()
            return {"status": "success"}
        except Exception as e:
            logger.error(f"Error PATCH {endpoint}: {str(e)}")
            raise

    async def delete(self, endpoint: str) -> Dict[str, Any]:
        try:
            response = await self.client.delete(endpoint)
            response.raise_for_status()
            # Handle empty responses for delete
            if response.content:
                return response.json()
            return {"status": "success"}
        except Exception as e:
            logger.error(f"Error DELETE {endpoint}: {str(e)}")
            raise

    async def close(self):
        await self.client.aclose()
