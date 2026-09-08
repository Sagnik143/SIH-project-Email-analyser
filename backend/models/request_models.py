from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class EmailAnalyzeRequest(BaseModel):
    raw: str = Field(..., description="Raw RFC 822 email text")

class IPLookupRequest(BaseModel):
    ip: str = Field(..., description="IP address to lookup")

class IPBatchLookupRequest(BaseModel):
    ips: List[str] = Field(..., description="List of IP addresses to lookup")

class CreateCaseRequest(BaseModel):
    name: str = Field(..., description="Case name / title")
    emails: Optional[List[str]] = Field(default=[], description="List of analyzed email IDs")
    notes: Optional[str] = Field(default="", description="Case notes / description")
    tags: Optional[List[str]] = Field(default=[], description="Tags for categorization")

class UpdateCaseRequest(BaseModel):
    name: Optional[str] = None
    status: Optional[str] = None
    emails: Optional[List[str]] = None
    notes: Optional[str] = None
    tags: Optional[List[str]] = None

class AddEmailToCaseRequest(BaseModel):
    emailId: str = Field(..., description="Email ID to add to case")
