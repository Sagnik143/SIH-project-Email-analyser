"""
Database persistence layer using TinyDB
Stores analyzed emails, cases, and forensic reports with thread safety.
"""

from tinydb import TinyDB, Query
import os
import threading
from config import DB_PATH

_lock = threading.Lock()
_db = TinyDB(DB_PATH)

cases_table = _db.table("cases")
reports_table = _db.table("reports")

def get_all_cases():
    with _lock:
        return cases_table.all()

def get_case(case_id: str):
    with _lock:
        Case = Query()
        res = cases_table.search(Case.id == case_id)
        return res[0] if res else None

def save_case(case_dict: dict):
    with _lock:
        Case = Query()
        existing = cases_table.search(Case.id == case_dict["id"])
        if existing:
            cases_table.update(case_dict, Case.id == case_dict["id"])
        else:
            cases_table.insert(case_dict)
    return case_dict

def delete_case(case_id: str):
    with _lock:
        Case = Query()
        deleted = cases_table.remove(Case.id == case_id)
        return len(deleted) > 0

def get_all_reports():
    with _lock:
        return reports_table.all()

def get_report(report_id: str):
    with _lock:
        Report = Query()
        res = reports_table.search(Report.id == report_id)
        return res[0] if res else None

def save_report(report_dict: dict):
    with _lock:
        Report = Query()
        existing = reports_table.search(Report.id == report_dict["id"])
        if existing:
            reports_table.update(report_dict, Report.id == report_dict["id"])
        else:
            reports_table.insert(report_dict)
    return report_dict

def delete_report(report_id: str):
    with _lock:
        Report = Query()
        deleted = reports_table.remove(Report.id == report_id)
        return len(deleted) > 0
