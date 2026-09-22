from fastapi import APIRouter, HTTPException
from .. import db

router = APIRouter()


@router.get("/history")
async def list_history():
    return await db.list_reports()


@router.get("/history/{analysis_id}")
async def get_history_item(analysis_id: str):
    report = await db.get_report(analysis_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return report


@router.delete("/history/{analysis_id}")
async def delete_history_item(analysis_id: str):
    if not await db.delete_report(analysis_id):
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return {"deleted": analysis_id}


@router.delete("/history")
async def delete_all_history():
    count = await db.delete_all_reports()
    return {"deleted_count": count}
