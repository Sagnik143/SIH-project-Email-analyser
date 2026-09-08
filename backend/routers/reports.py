"""
Reports Router
Endpoints for querying and managing forensic analysis reports.
"""

from fastapi import APIRouter, HTTPException
from data.database import get_all_reports, get_report, delete_report

router = APIRouter(prefix="/api/reports", tags=["Forensic Reports"])

@router.get("")
async def list_reports():
    return get_all_reports()

@router.get("/{report_id}")
async def get_single_report(report_id: str):
    rep = get_report(report_id)
    if not rep:
        raise HTTPException(status_code=404, detail="Report not found")
    return rep

@router.delete("/{report_id}")
async def remove_report(report_id: str):
    success = delete_report(report_id)
    if not success:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"success": True, "message": f"Report {report_id} deleted"}
