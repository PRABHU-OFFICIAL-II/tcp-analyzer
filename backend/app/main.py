from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from . import db
from .routes.analysis import router as analysis_router
from .routes.history import router as history_router
from .routes.export import router as export_router
from .routes.compare import router as compare_router
from .routes.settings import router as settings_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    yield


app = FastAPI(title="TCP Analyzer API", version="3.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analysis_router, prefix="/api")
app.include_router(history_router, prefix="/api")
app.include_router(export_router, prefix="/api")
app.include_router(compare_router, prefix="/api")
app.include_router(settings_router, prefix="/api")
