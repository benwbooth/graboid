"""JSON API endpoints for Graboid with key authentication."""

import hashlib
import logging
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["api"])


# =============================================================================
# Pydantic Models
# =============================================================================


class JobCreateRequest(BaseModel):
    """Request to create a new job."""

    prompt: str = Field(..., description="Task description for the LLM agent")
    source_url: str = Field(default="", description="Starting URL (optional)")
    credential_name: str | None = Field(default=None, description="Credential to use for authentication")
    file_filter: list[str] = Field(default_factory=list, description="Glob patterns to filter files")
    destination_path: str = Field(default="", description="Destination path for downloaded files")
    file_operation: str = Field(default="copy", description="File operation: copy, hardlink, symlink, reflink, path_only")
    priority: int = Field(default=0, description="Job priority (higher = processed first)")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class JobResponse(BaseModel):
    """Job information response."""

    id: str
    created_at: datetime
    updated_at: datetime
    prompt: str
    source_url: str
    credential_name: str | None
    file_filter: list[str]
    destination_path: str
    file_operation: str
    status: str
    priority: int
    progress_percent: float
    progress_message: str
    current_phase: str
    found_urls: list[str]
    downloaded_files: list[str]
    final_paths: list[str]
    error_message: str
    metadata: dict[str, Any]


class JobListResponse(BaseModel):
    """Response containing list of jobs."""

    jobs: list[JobResponse]
    total: int
    offset: int
    limit: int


class CredentialCreateRequest(BaseModel):
    """Request to create a credential."""

    name: str = Field(..., description="Unique name for the credential")
    username: str = Field(..., description="Username/login")
    password: str = Field(..., description="Password/secret")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class CredentialListResponse(BaseModel):
    """Response listing credential names."""

    credentials: list[str]


class ApiKeyResponse(BaseModel):
    """Response with API key."""

    api_key: str


class ErrorResponse(BaseModel):
    """Error response."""

    error: str
    detail: str | None = None


# =============================================================================
# API Key Authentication
# =============================================================================


def generate_api_key() -> str:
    """Generate a new API key."""
    return secrets.token_urlsafe(32)


def get_api_key_from_config(request: Request) -> str:
    """Get API key from app state config."""
    app_state = getattr(request.app, "state", None)
    if app_state and hasattr(app_state, "api_key"):
        return app_state.api_key
    return ""


async def verify_api_key(
    request: Request,
    x_api_key: str | None = Header(default=None),
    api_key: str | None = Query(default=None),
) -> str:
    """Verify API key from header or query param."""
    # Get expected key
    expected_key = get_api_key_from_config(request)

    if not expected_key:
        # No key configured - allow access (development mode)
        return ""

    # Check header first, then query param
    provided_key = x_api_key or api_key

    if not provided_key:
        raise HTTPException(
            status_code=401,
            detail="API key required. Provide via X-API-Key header or api_key query param",
        )

    if not secrets.compare_digest(provided_key, expected_key):
        raise HTTPException(status_code=403, detail="Invalid API key")

    return provided_key


# =============================================================================
# Job Endpoints
# =============================================================================


@router.post("/jobs", response_model=JobResponse)
async def create_job(
    request: Request,
    job_request: JobCreateRequest,
    _api_key: str = Depends(verify_api_key),
):
    """Submit a new job to the queue."""
    from ..jobs import Job, JobQueue

    queue: JobQueue | None = getattr(request.app.state, "job_queue", None)
    if not queue:
        raise HTTPException(status_code=503, detail="Job queue not initialized")

    job = await queue.submit(
        prompt=job_request.prompt,
        source_url=job_request.source_url,
        credential_name=job_request.credential_name,
        file_filter=job_request.file_filter,
        destination_path=job_request.destination_path,
        file_operation=job_request.file_operation,
        priority=job_request.priority,
        metadata=job_request.metadata,
    )

    return _job_to_response(job)


@router.get("/jobs", response_model=JobListResponse)
async def list_jobs(
    request: Request,
    status: str | None = Query(default=None, description="Filter by status"),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    _api_key: str = Depends(verify_api_key),
):
    """List jobs with optional filtering."""
    from ..jobs import JobQueue, JobStatus

    queue: JobQueue | None = getattr(request.app.state, "job_queue", None)
    if not queue:
        raise HTTPException(status_code=503, detail="Job queue not initialized")

    status_filter = JobStatus(status) if status else None
    jobs = await queue.list_jobs(status=status_filter, limit=limit, offset=offset)
    total = await queue.db.count_jobs(status_filter)

    return JobListResponse(
        jobs=[_job_to_response(j) for j in jobs],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.get("/jobs/{job_id}", response_model=JobResponse)
async def get_job(
    request: Request,
    job_id: str,
    _api_key: str = Depends(verify_api_key),
):
    """Get job details by ID."""
    from ..jobs import JobQueue

    queue: JobQueue | None = getattr(request.app.state, "job_queue", None)
    if not queue:
        raise HTTPException(status_code=503, detail="Job queue not initialized")

    job = await queue.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    return _job_to_response(job)


@router.delete("/jobs/{job_id}")
async def cancel_job(
    request: Request,
    job_id: str,
    _api_key: str = Depends(verify_api_key),
):
    """Cancel a pending or running job."""
    from ..jobs import JobQueue

    queue: JobQueue | None = getattr(request.app.state, "job_queue", None)
    if not queue:
        raise HTTPException(status_code=503, detail="Job queue not initialized")

    success = await queue.cancel_job(job_id)
    if not success:
        raise HTTPException(status_code=404, detail="Job not found or already completed")

    return {"status": "cancelled", "job_id": job_id}


@router.get("/jobs/{job_id}/stream")
async def stream_job_progress(
    request: Request,
    job_id: str,
    _api_key: str = Depends(verify_api_key),
):
    """Stream job progress via Server-Sent Events."""
    import asyncio
    import json

    from ..jobs import JobQueue, JobStatus

    queue: JobQueue | None = getattr(request.app.state, "job_queue", None)
    if not queue:
        raise HTTPException(status_code=503, detail="Job queue not initialized")

    job = await queue.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    async def event_generator():
        last_update = None

        while True:
            # Check if client disconnected
            if await request.is_disconnected():
                break

            current_job = await queue.get_job(job_id)
            if not current_job:
                yield {
                    "event": "error",
                    "data": json.dumps({"error": "Job not found"}),
                }
                break

            # Send update if changed
            update_key = (current_job.updated_at, current_job.progress_percent)
            if update_key != last_update:
                last_update = update_key
                yield {
                    "event": "progress",
                    "data": json.dumps({
                        "job_id": current_job.id,
                        "status": current_job.status.value,
                        "phase": current_job.current_phase.value,
                        "progress_percent": current_job.progress_percent,
                        "progress_message": current_job.progress_message,
                    }),
                }

            # Check if complete
            if current_job.status in (
                JobStatus.COMPLETE,
                JobStatus.FAILED,
                JobStatus.CANCELLED,
            ):
                yield {
                    "event": "complete",
                    "data": json.dumps(_job_to_response(current_job).model_dump(mode="json")),
                }
                break

            await asyncio.sleep(0.5)

    return EventSourceResponse(event_generator())


@router.get("/jobs/{job_id}/screenshots")
async def get_job_screenshots(
    request: Request,
    job_id: str,
    _api_key: str = Depends(verify_api_key),
):
    """Get screenshots for a job."""
    import base64

    from ..jobs import JobQueue

    queue: JobQueue | None = getattr(request.app.state, "job_queue", None)
    if not queue:
        raise HTTPException(status_code=503, detail="Job queue not initialized")

    screenshots = await queue.get_screenshots(job_id)

    return {
        "job_id": job_id,
        "screenshots": [
            {
                "id": s.id,
                "timestamp": s.timestamp.isoformat(),
                "url": s.url,
                "phase": s.phase,
                "data_base64": base64.b64encode(s.screenshot_data).decode() if s.screenshot_data else None,
            }
            for s in screenshots
        ],
    }


# =============================================================================
# API Key Management
# =============================================================================


@router.post("/key/regenerate", response_model=ApiKeyResponse)
async def regenerate_api_key(
    request: Request,
    _api_key: str = Depends(verify_api_key),
):
    """Regenerate the API key."""
    new_key = generate_api_key()

    # Update in app state
    if hasattr(request.app.state, "api_key"):
        request.app.state.api_key = new_key

    # TODO: Persist to config file

    return ApiKeyResponse(api_key=new_key)


# =============================================================================
# Credential Endpoints
# =============================================================================


@router.get("/credentials", response_model=CredentialListResponse)
async def list_credentials(
    request: Request,
    _api_key: str = Depends(verify_api_key),
):
    """List stored credential names."""
    from ..credentials import CredentialStore

    store: CredentialStore | None = getattr(request.app.state, "credential_store", None)
    if not store:
        raise HTTPException(status_code=503, detail="Credential store not initialized")

    names = store.list()
    return CredentialListResponse(credentials=names)


@router.post("/credentials")
async def create_credential(
    request: Request,
    cred_request: CredentialCreateRequest,
    _api_key: str = Depends(verify_api_key),
):
    """Add a new credential."""
    from ..credentials import CredentialStore

    store: CredentialStore | None = getattr(request.app.state, "credential_store", None)
    if not store:
        raise HTTPException(status_code=503, detail="Credential store not initialized")

    store.add(
        name=cred_request.name,
        username=cred_request.username,
        password=cred_request.password,
        metadata=cred_request.metadata,
    )

    return {"status": "created", "name": cred_request.name}


@router.delete("/credentials/{name}")
async def delete_credential(
    request: Request,
    name: str,
    _api_key: str = Depends(verify_api_key),
):
    """Delete a credential."""
    from ..credentials import CredentialStore

    store: CredentialStore | None = getattr(request.app.state, "credential_store", None)
    if not store:
        raise HTTPException(status_code=503, detail="Credential store not initialized")

    success = store.delete(name)
    if not success:
        raise HTTPException(status_code=404, detail="Credential not found")

    return {"status": "deleted", "name": name}


# =============================================================================
# Helpers
# =============================================================================


def _job_to_response(job) -> JobResponse:
    """Convert Job to JobResponse."""
    return JobResponse(
        id=job.id,
        created_at=job.created_at,
        updated_at=job.updated_at,
        prompt=job.prompt,
        source_url=job.source_url,
        credential_name=job.credential_name,
        file_filter=job.file_filter,
        destination_path=job.destination_path,
        file_operation=job.file_operation.value,
        status=job.status.value,
        priority=job.priority,
        progress_percent=job.progress_percent,
        progress_message=job.progress_message,
        current_phase=job.current_phase.value,
        found_urls=job.found_urls,
        downloaded_files=job.downloaded_files,
        final_paths=job.final_paths,
        error_message=job.error_message,
        metadata=job.metadata,
    )
