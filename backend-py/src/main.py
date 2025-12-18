import time
import uuid
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

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


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup and shutdown events."""
    # Startup
    logger.info(
        "Application startup complete",
        service="backend-py",
        version="0.1.0",
        api_prefix=api_prefix_v1,
    )
    yield
    # Shutdown
    logger.info("Application shutdown initiated")


app = FastAPI(
    title=OpenAPIInfo["title"],
    version=OpenAPIInfo["version"],
    openapi_tags=tags_metadata,
    lifespan=lifespan,
)


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
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Add filter to the logger


@app.get("/")
async def root():
    logger.info("Root endpoint accessed", endpoint="/")
    return {"message": "Route verification endpoints"}


app.include_router(user_router, prefix=api_prefix_v1 + "/user", tags=["User CRUD"])
