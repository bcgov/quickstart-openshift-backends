import time
import uuid

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from src.v1.routes.user_routes import router as user_router

# Initialize production-grade logging first
logger = structlog.get_logger(__name__)

api_prefix_v1 = "/api/v1"

OpenAPIInfo = {
    "title": "FastAPI template for quickstart openshift",
    "version": "0.1.0",
    "description": "A boilerplate for FastAPI with SQLAlchemy, Postgres",
}
tags_metadata = [
    {
        "name": "FastAPI template for quickstart openshift",
        "description": "A quickstart template for FastAPI with SQLAlchemy, Postgres",
    },
]

app = FastAPI(
    title=OpenAPIInfo["title"],
    version=OpenAPIInfo["version"],
    openapi_tags=tags_metadata,
)


# Security headers middleware to address ZAP penetration test findings
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware to add security headers and address ZAP penetration test findings.
    
    Addresses the following ZAP alerts:
    - Proxy Disclosure [40025]
    - Strict-Transport-Security Header Not Set [10035]
    - X-Content-Type-Options Header Missing [10021]
    - Re-examine Cache-control Directives [10015]
    - Storable and Cacheable Content [10049]
    """

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Security headers to address ZAP alerts

        # X-Content-Type-Options: Prevents MIME type sniffing
        # Addresses: X-Content-Type-Options Header Missing [10021]
        response.headers["X-Content-Type-Options"] = "nosniff"

        # X-Frame-Options: Prevents clickjacking attacks
        response.headers["X-Frame-Options"] = "DENY"

        # Content-Security-Policy: Prevents XSS, clickjacking, and other code injection attacks
        # A restrictive policy for APIs
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"

        # Strict-Transport-Security: Enforces HTTPS
        # Addresses: Strict-Transport-Security Header Not Set [10035]
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

        # Referrer-Policy: Controls referrer information
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Hide server information (addresses Proxy Disclosure alert [40025])
        # Remove Server header if present
        if "Server" in response.headers:
            del response.headers["Server"]
        # Also remove any proxy-related headers that might leak information
        if "X-Powered-By" in response.headers:
            del response.headers["X-Powered-By"]
        if "X-AspNet-Version" in response.headers:
            del response.headers["X-AspNet-Version"]

        # Cache-Control headers (addresses Re-examine Cache-control Directives [10015]
        # and Storable and Cacheable Content [10049])
        # For API endpoints, typically we don't want caching
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        else:
            # For static content, allow some caching but with revalidation
            response.headers["Cache-Control"] = "public, max-age=3600, must-revalidate"

        return response


# Logging middleware for request tracking
@app.middleware("http")
async def logging_middleware(request: Request, call_next):
    start_time = time.time()
    correlation_id = str(uuid.uuid4())

    # Add correlation ID to logger context
    request_logger = logger.bind(
        correlation_id=correlation_id,
        method=request.method,
        url=str(request.url),
        client_ip=request.client.host if request.client else None,
    )

    request_logger.info("Request started")

    response = await call_next(request)

    process_time = time.time() - start_time

    request_logger.info(
        "Request completed",
        status_code=response.status_code,
        duration_ms=round(process_time * 1000, 2),
    )

    return response


origins: list[str] = [
    "http://localhost*",
]
# Add CORS middleware first (it will execute last due to LIFO order)
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add security headers middleware after CORS (it will execute first and apply headers last)
# This ensures security headers take precedence over CORS headers
app.add_middleware(SecurityHeadersMiddleware)


# Add filter to the logger


@app.get("/")
async def root():
    logger.info("Root endpoint accessed", endpoint="/")
    return {"message": "Route verification endpoints"}


app.include_router(user_router, prefix=api_prefix_v1 + "/user", tags=["User CRUD"])


# Startup event
@app.on_event("startup")
async def startup_event():
    logger.info(
        "Application startup complete",
        service="backend-py",
        version="0.1.0",
        api_prefix=api_prefix_v1,
    )


# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Application shutdown initiated")
