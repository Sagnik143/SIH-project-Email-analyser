"""
Geolocation Router
Endpoints for on-demand IP intelligence and geolocation lookups.
"""

from fastapi import APIRouter, HTTPException
from models.request_models import IPLookupRequest, IPBatchLookupRequest
from engine.ip_intelligence import lookup_ip, batch_lookup_ips

router = APIRouter(prefix="/api/geo", tags=["Geolocation"])

@router.post("/lookup")
async def single_ip_lookup(payload: IPLookupRequest):
    if not payload.ip or not payload.ip.strip():
        raise HTTPException(status_code=400, detail="Missing or invalid IP address")
    result = await lookup_ip(payload.ip.strip())
    return result

@router.post("/batch")
async def batch_ip_lookup(payload: IPBatchLookupRequest):
    if not payload.ips:
        return []
    results = await batch_lookup_ips(payload.ips[:10])
    return results
