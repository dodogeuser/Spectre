"""Local application with authenticated case management and liveness endpoint."""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

from app.config import Settings, get_settings
from app.logging_config import configure_logging
from app.db.session import make_session_factory
from app.api import auth, cases, targets, collectors, domain, ip, web, correlation, investigation, findings, ai, reports, active
from app.active.client import ActiveClient
from app.ai.provider import OllamaProvider
from app.collectors.registry import default_registry
from app.security.rate_limit import HostRateLimiter
from app.services.collection import admission_limit
from app.security.login_limit import LoginLimiter
from app.version import VERSION, RELEASE_STATUS

STATIC_DIR = Path(__file__).resolve().parent / "static"


def create_app(settings: Settings | None = None, session_factory=None) -> FastAPI:
    config = settings if settings is not None else get_settings()

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        configure_logging(config)
        logging.getLogger("spectre").info("SPECTRE foundation started")
        yield
        logging.getLogger("spectre").info("SPECTRE foundation stopped")

    application = FastAPI(title=config.app_name, version=VERSION, lifespan=lifespan)
    application.state.login_limiter = LoginLimiter()
    application.state.settings = config
    application.state.session_factory = session_factory or make_session_factory(config)
    application.state.collector_registry = default_registry(config)
    application.state.host_limiter = HostRateLimiter()
    application.state.collector_admission = admission_limit()
    application.state.ai_provider = OllamaProvider(config)
    application.state.active_limiter = HostRateLimiter()
    application.state.active_client_factory = ActiveClient
    application.include_router(auth.router)
    application.include_router(cases.router)
    application.include_router(targets.router)
    application.include_router(collectors.router)
    application.include_router(domain.router)
    application.include_router(ip.router)
    application.include_router(web.router)
    application.include_router(correlation.router)
    application.include_router(investigation.router)
    application.include_router(findings.router)
    application.include_router(ai.router)
    application.include_router(reports.router)
    application.include_router(active.router)

    @application.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        defaults = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Cache-Control": "no-store",
        }
        if request.url.path == "/":
            defaults["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
        for key,value in defaults.items():response.headers.setdefault(key,value)
        return response

    @application.exception_handler(RequestValidationError)
    async def invalid_request(request, exc):
        # Validation errors must not echo submitted passwords or other inputs.
        return JSONResponse(status_code=422, content={"detail": [
            {"loc": list(error["loc"]), "msg": error["msg"], "type": error["type"]}
            for error in exc.errors()
        ]})

    @application.exception_handler(SQLAlchemyError)
    async def database_failure(request, exc):
        logging.getLogger("spectre").error("Database operation failed")
        return JSONResponse(status_code=503, content={"detail": "Database unavailable; check local configuration and migrations"})
    application.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @application.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @application.get("/", include_in_schema=False)
    async def landing() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @application.get("/version")
    async def version():
        return {"version": VERSION, "status": RELEASE_STATUS}

    return application


app = create_app()
