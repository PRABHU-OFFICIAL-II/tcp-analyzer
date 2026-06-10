import json
from pathlib import Path
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from .. import thresholds as thr

router = APIRouter()

_PATH = Path(__file__).parent.parent.parent / "data" / "thresholds.json"


@router.get("/settings/thresholds")
def get_thresholds():
    return thr.all_thresholds()


@router.put("/settings/thresholds")
def update_thresholds(body: dict):
    try:
        # Merge with existing file content, not defaults
        existing = {}
        if _PATH.exists():
            existing = json.loads(_PATH.read_text())
        for section, vals in body.items():
            if section.startswith("_"):
                continue
            if section not in existing:
                existing[section] = {}
            existing[section].update(vals)
        _PATH.write_text(json.dumps(existing, indent=2))
        thr.reload()
        return thr.all_thresholds()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/settings/thresholds/reset")
def reset_thresholds():
    try:
        if _PATH.exists():
            _PATH.unlink()
        thr.reload()
        return thr.all_thresholds()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
