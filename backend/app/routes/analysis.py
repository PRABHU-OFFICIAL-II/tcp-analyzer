import os
import tempfile
from fastapi import APIRouter, UploadFile, File, HTTPException
from ..analyzers.engine import run_analysis
from ..models.report import AnalysisReport

router = APIRouter()


@router.post("/analyze", response_model=AnalysisReport)
async def analyze_pcap(file: UploadFile = File(...)):
    if not file.filename.endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(status_code=400, detail="Only .pcap, .pcapng, and .cap files are accepted.")

    contents = await file.read()
    if len(contents) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(contents)
        tmp_path = tmp.name

    try:
        report = run_analysis(tmp_path, file.filename)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
    finally:
        os.unlink(tmp_path)

    return report


@router.get("/health")
def health():
    return {"status": "ok"}
