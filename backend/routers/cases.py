"""
Cases Router
CRUD endpoints for forensic case investigation management.
"""

from fastapi import APIRouter, HTTPException
import time
from datetime import datetime
from models.request_models import CreateCaseRequest, UpdateCaseRequest, AddEmailToCaseRequest
from data.database import get_all_cases, get_case, save_case, delete_case

router = APIRouter(prefix="/api/cases", tags=["Case Management"])

@router.get("")
async def list_cases():
    return get_all_cases()

@router.post("")
async def create_case(payload: CreateCaseRequest):
    case_id = f"CASE-{int(time.time() * 1000)}"
    now = datetime.utcnow().isoformat() + "Z"
    new_case = {
        "id": case_id,
        "name": payload.name,
        "status": "new",
        "emails": payload.emails or [],
        "notes": payload.notes or "",
        "tags": payload.tags or [],
        "createdAt": now,
        "updatedAt": now,
    }
    saved = save_case(new_case)
    return saved

@router.get("/{case_id}")
async def get_single_case(case_id: str):
    case_obj = get_case(case_id)
    if not case_obj:
        raise HTTPException(status_code=404, detail="Case not found")
    return case_obj

@router.put("/{case_id}")
async def update_case(case_id: str, payload: UpdateCaseRequest):
    case_obj = get_case(case_id)
    if not case_obj:
        raise HTTPException(status_code=404, detail="Case not found")

    updates = payload.model_dump(exclude_unset=True)
    for k, v in updates.items():
        if v is not None:
            case_obj[k] = v
    case_obj["updatedAt"] = datetime.utcnow().isoformat() + "Z"

    saved = save_case(case_obj)
    return saved

@router.delete("/{case_id}")
async def remove_case(case_id: str):
    success = delete_case(case_id)
    if not success:
        raise HTTPException(status_code=404, detail="Case not found")
    return {"success": True, "message": f"Case {case_id} deleted"}

@router.post("/{case_id}/emails")
async def add_email_to_case(case_id: str, payload: AddEmailToCaseRequest):
    case_obj = get_case(case_id)
    if not case_obj:
        raise HTTPException(status_code=404, detail="Case not found")

    email_id = payload.emailId
    if "emails" not in case_obj:
        case_obj["emails"] = []
    if email_id not in case_obj["emails"]:
        case_obj["emails"].append(email_id)

    case_obj["updatedAt"] = datetime.utcnow().isoformat() + "Z"
    saved = save_case(case_obj)
    return saved
