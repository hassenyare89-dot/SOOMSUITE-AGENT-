from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import router
from app.core.config import get_settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


settings = get_settings()
app = FastAPI(
    title="SAMIIR + FATMA Secure AI Platform",
    version="0.1.0",
    lifespan=lifespan,
    docs_url=None if settings.environment == "production" else "/docs",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins.split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "Idempotency-Key", "X-Hub-Signature-256"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    if int(request.headers.get("content-length", "0")) > settings.max_request_bytes:
        return JSONResponse({"detail": "request too large"}, 413)
    response = await call_next(request)
    response.headers.update(
        {
            "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
            "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        }
    )
    return response


app.include_router(router)
