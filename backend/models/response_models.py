from pydantic import BaseModel
from typing import List, Optional, Dict, Any

class GenericResponse(BaseModel):
    success: bool
    message: Optional[str] = None
    data: Optional[Any] = None

class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
