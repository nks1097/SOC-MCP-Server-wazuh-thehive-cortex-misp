from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

class IOC(BaseModel):
    value: str
    type: str  # ipv4, ipv6, domain, url, md5, sha256, etc.
    context: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    
class WazuhAlert(BaseModel):
    id: str
    timestamp: datetime
    rule_id: str
    rule_level: int
    rule_description: str
    agent_id: str
    agent_name: str
    full_log: str
    decoder_name: Optional[str] = None
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    iocs: List[IOC] = Field(default_factory=list)
    raw_data: Dict[str, Any] = Field(default_factory=dict)
