from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict
from pydantic import BaseModel, Field
import uuid

class Severity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class ActionType(Enum):
    BLOCK_IP = "block_ip"
    KILL_PROCESS = "kill_process"
    ISOLATE_HOST = "isolate_host"
    NOTIFY_HUMAN = "notify_human"
    INVESTIGATE = "investigate"

class Alert(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.now)
    type: str
    source: str
    severity: Severity
    ioc_confidence: float  # 0.0 to 1.0
    asset_criticality: float # 0.0 to 1.0
    description: str
    metadata: Dict = {}

class ResponseAction(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: ActionType
    target: str
    security_gain: float
    operational_cost: float
    business_risk: float
    status: str = "pending"

class Incident(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    alert: Alert
    priority_score: float = 0.0
    blast_radius: float = 0.0
    recommended_actions: List[ResponseAction] = []
    final_actions: List[ResponseAction] = []
    status: str = "open"
    created_at: datetime = Field(default_factory=datetime.now)
    resolved_at: Optional[datetime] = None
