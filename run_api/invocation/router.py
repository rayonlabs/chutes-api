"""
Invocations router.
"""

import pybase64 as base64
import pickle
import gzip
import orjson as json
from fastapi import APIRouter, Depends, HTTPException, status, Request
from starlette.responses import StreamingResponse
from sqlalchemy import text, String
from sqlalchemy.ext.asyncio import AsyncSession
from run_api.chute.util import get_chute_by_id_or_name, invoke
from run_api.user.schemas import User
from run_api.user.service import get_current_user
from run_api.database import get_db_session
from run_api.invocation.schemas import Report
from run_api.instance.util import discover_chute_targets

router = APIRouter()
host_invocation_router = APIRouter()

CHECK_EXISTS = text(
    "SELECT user_id, report_reason, to_char(date_trunc('week', started_at), 'IYYY_IW') AS table_suffix FROM invocations WHERE invocation_id = :invocation_id"
).columns(user_id=String, table_suffix=String, report_reason=String)
SAVE_REPORT = "UPDATE partitioned_invocations_{table_suffix} SET report_reason = :report_reason, reported_at = CURRENT_TIMESTAMP WHERE invocation_id = :invocation_id RETURNING reported_at"


@router.post("/{invocation_id}/report")
async def report_invocation(
    invocation_id: str,
    report: Report,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user()),
):
    result = await db.execute(CHECK_EXISTS, {"invocation_id": invocation_id})
    item = result.fetchone()
    user_id, existing_reason, table_suffix = None, None, None
    if item:
        user_id, existing_reason, table_suffix = item
    if not item or user_id != current_user.user_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invocation not found, or does not belong to you",
        )
    if existing_reason is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A report has already been filed for this invocation",
        )
    result = await db.execute(
        text(SAVE_REPORT.format(table_suffix=table_suffix)),
        {
            "report_reason": report.reason,
            "invocation_id": invocation_id,
        },
    )
    await db.commit()
    reported_at = result.scalar()
    return {
        "status": f"report received for {invocation_id=} @ {reported_at}",
    }


@host_invocation_router.api_route(
    "{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"]
)
async def hostname_invocation(
    request: Request,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user()),
):
    # This call will perform auth/access checks.
    chute = await get_chute_by_id_or_name(request.state.chute_id, db, current_user)

    # Identify the cord that we'll trying to access by the public API path and method.
    selected_cord = None
    request_body = (
        await request.json() if request.method in ("POST", "PUT", "PATCH") else {}
    )
    request_params = request.query_params._dict if request.query_params else {}
    stream = request_body.get("stream", request_params.get("stream", False))
    for cord in chute.cords:
        public_path = cord.get("public_api_path", None)
        if public_path and public_path == request.url.path:
            if cord.get(
                "public_api_method", "POST"
            ) == request.method and stream == cord.get("stream"):
                selected_cord = cord
                break
    if not selected_cord:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="No matching cord found!"
        )

    # Wrap up the args/kwargs in the way the miner execution service expects them.
    args = base64.b64encode(gzip.compress(pickle.dumps(tuple()))).decode()
    if chute.standard_template == "vllm":
        request_body = {"json": request_body, "params": request_params}
    kwargs = base64.b64encode(gzip.compress(pickle.dumps(request_body))).decode()
    targets = await discover_chute_targets(db, chute.chute_id)
    if not targets:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No instances available (yet) for {chute_id=}",
        )

    # To stream, or not to stream.
    if stream:

        async def _stream_response():
            async for chunk in invoke(
                chute,
                current_user.user_id,
                selected_cord["path"],
                selected_cord["function"],
                stream,
                args,
                kwargs,
                targets,
            ):
                if chunk.startswith('data: {"result"'):
                    yield json.loads(chunk[6:])["result"]

        return StreamingResponse(_stream_response())

    # Non-streamed (which we actually do stream but we'll just return the first item)
    error = None
    async for chunk in invoke(
        chute,
        current_user.user_id,
        selected_cord["path"],
        selected_cord["function"],
        stream,
        args,
        kwargs,
        targets,
    ):
        if chunk.startswith('data: {"result"'):
            return json.loads(chunk[6:])["result"]
        elif chunk.startswith('data: {"error"'):
            error = json.loads(chunk[6:])["error"]
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=error or "No result returned from upstream",
    )