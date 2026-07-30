from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

import os

class Settings(BaseSettings):
    # Wazuh Settings
    WAZUH_HOST: str
    WAZUH_USER: str
    WAZUH_PASS: str
    WAZUH_API_PORT: int = 55000
    WAZUH_SSH_PORT: int = 22
    WAZUH_SSH_USER: str
    WAZUH_SSH_PASS: str
    
    # Wazuh Indexer Settings
    WAZUH_INDEXER_HOST: Optional[str] = None
    WAZUH_INDEXER_USER: Optional[str] = None
    WAZUH_INDEXER_PASS: Optional[str] = None
    WAZUH_INDEXER_PORT: Optional[int] = 9200
    
    # TheHive Settings
    THEHIVE_URL: str
    THEHIVE_API_KEY: str
    
    # Cortex Settings
    CORTEX_URL: str
    CORTEX_API_KEY: str
    
    # MISP Settings
    MISP_URL: str
    MISP_API_KEY: str
    MISP_VERIFY_SSL: bool = False
    
    # Docker Host SSH Settings (where TheHive, Cortex, MISP run)
    DOCKER_HOST_SSH_IP: str
    DOCKER_HOST_SSH_PORT: int = 22
    DOCKER_HOST_SSH_USER: str
    DOCKER_HOST_SSH_PASS: str
    
    # App Settings
    LOG_LEVEL: str = "INFO"
    FAST_MCP_NAME: str = "SOC-MCP-Server"
    FAST_MCP_PORT: int = 8000
    
    model_config = SettingsConfigDict(
        env_file=os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), ".env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
