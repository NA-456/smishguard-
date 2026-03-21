"""
SmishGuard — SMS Phishing Detection API
FastAPI backend with AfricasTalking webhook integration
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging
import time

from app.routers import analyze, webhook, admin
from app.models.schemas import HealthResponse
from app.config import settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("smishguard")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("SmishGuard API starting up...")
    logger.info(f"Environment : {settings.environment}")
    logger.info(f"Rules loaded: {settings.total_rules} total ({settings.gh_rules} Ghana-specific)")
    yield
    logger.info("SmishGuard API shutting down.")


app = FastAPI(
    title="SmishGuard API",
    description=(
        "Offline-capable SMS phishing detection API with Ghana/West Africa "
        "rule sets and AfricasTalking webhook integration."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    ms = (time.perf_counter() - start) * 1000
    response.headers["X-Process-Time-Ms"] = f"{ms:.2f}"
    return response


app.include_router(analyze.router, prefix="/api/v1",       tags=["Analysis"])
app.include_router(webhook.router, prefix="/webhook",      tags=["AfricasTalking"])
app.include_router(admin.router,   prefix="/api/v1/admin", tags=["Admin"])


@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health():
    return HealthResponse(
        status="ok",
        version="1.0.0",
        environment=settings.environment,
        rules_loaded=settings.total_rules,
        gh_rules=settings.gh_rules,
    )


@app.get("/", tags=["System"])
async def root():
    return {"service": "SmishGuard", "docs": "/docs", "health": "/health"}
