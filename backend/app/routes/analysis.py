import os
import asyncio
import tempfile
from fastapi import APIRouter, UploadFile, File, HTTPException, Request
from ..analyzers.engine import run_analysis
from ..models.report import AnalysisReport

router = APIRouter()

MAX_PCAP_MB = int(os.environ.get("MAX_PCAP_MB", "200"))
_MAX_BYTES = MAX_PCAP_MB * 1024 * 1024


@router.post("/analyze", response_model=AnalysisReport)
async def analyze_pcap(request: Request, file: UploadFile = File(...)):
    if not file.filename.endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(status_code=400, detail="Only .pcap, .pcapng, and .cap files are accepted.")

    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > _MAX_BYTES:
        raise HTTPException(status_code=413, detail=f"File too large. Maximum {MAX_PCAP_MB} MB allowed.")

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            tmp_path = tmp.name
            size = 0
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > _MAX_BYTES:
                    raise HTTPException(status_code=413, detail=f"File too large. Maximum {MAX_PCAP_MB} MB allowed.")
                tmp.write(chunk)

        if size == 0:
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")

        loop = asyncio.get_event_loop()
        report = await loop.run_in_executor(
            None, lambda: run_analysis(tmp_path, file.filename, save=False)
        )
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)

    return report


@router.get("/health")
def health():
    return {"status": "ok"}
