"""
User logic/code.
"""

from typing import Optional
from sqlalchemy import exists
from sqlalchemy.future import select
from fastapi import APIRouter, Header, Request, HTTPException, Security, status
from substrateinterface import Keypair
from run_api.config import settings
from run_api.metasync import MetagraphNode
from run_api.database import SessionLocal
from run_api.user.schemas import User
from run_api.api_key.util import get_and_check_api_key
from fastapi.security import APIKeyHeader
from run_api.constants import HOTKEY_HEADER, SIGNATURE_HEADER, AUTHORIZATION_HEADER
from loguru import logger
from run_api.constants import NONCE_HEADER
from run_api.util import nonce_is_valid, get_signing_message
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter()
api_key_header = APIKeyHeader(name="Authorization", auto_error=False)


def get_current_user(
    purpose: str = None,
    registered_to: int = None,
    raise_not_found: bool = True,  # NOTE: Should raise not found by default - assume we are getting the user for a reason
):
    """
    Authentication dependency builder.
    """

    async def _authenticate(
        request: Request,
        api_key: Optional[str] = Security(api_key_header),
        hotkey: str = Header(..., alias=HOTKEY_HEADER),
        signature: str = Header(..., alias=SIGNATURE_HEADER),
        nonce: str = Header(..., alias=NONCE_HEADER),
        authorization: str = Header(None, alias=AUTHORIZATION_HEADER),
    ):
        """
        Helper to authenticate requests.
        """

        use_hotkey_auth = hotkey and signature
        # If not using hotkey auth, then just use the API key
        if not use_hotkey_auth:
            logger.debug("No hotkey or signature found in request headers")
            # API key validation.
            if authorization:
                token = authorization.split(" ")[-1]
                if token:
                    api_key = await get_and_check_api_key(token, request)
                    request.state.api_key = api_key
                    return api_key.user
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key not found :(",
            )

        # Otherwise we are using hotkey auth, so need to check the nonce
        # and check the message was signed correctly
        if not nonce_is_valid(nonce):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid nonce!",
            )

        # Now get the Signing message

        body_sha256 = getattr(request.state, "body_sha256", None)

        signing_message = get_signing_message(
            hotkey=hotkey,
            nonce=nonce,
            payload_hash=body_sha256,
            purpose=purpose,
            payload_str=None,
        )

        if not signing_message:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Bad signing message: {signing_message}",
            )

        # Verify the signature
        try:
            signature_hex = bytes.fromhex(signature)
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid signature: {signature}, with error: {e}",
            )
        try:
            keypair = Keypair(hotkey)
            if not keypair.verify(signing_message, signature_hex):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Invalid request signature for hotkey {hotkey}. Message: {signing_message}",
                )
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid request signature for hotkey {hotkey}. Message: {signing_message}",
            ) from e

        # Requires a hotkey registered to a netuid?
        if registered_to is not None:
            async with SessionLocal() as session:
                if not (
                    await session.execute(
                        select(
                            exists()
                            .where(MetagraphNode.hotkey == hotkey)
                            .where(MetagraphNode.netuid == registered_to)
                        )
                    )
                ).scalar():
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail=f"Hotkey is not registered on netuid {settings.netuid}",
                    )

        # Fetch the actual user.
        # NOTE: We should have a standard way to get this session
        async with SessionLocal() as session:
            session: AsyncSession  # For nice type hinting for IDE's
            result = await session.execute(select(User).where(User.hotkey == hotkey))

            user = result.scalar_one_or_none()
            logger.debug(
                f"User: {user}, not user: {not user}, user is none: {user is None}, raise not found: {raise_not_found}"
            )
            if not user and raise_not_found:
                if use_hotkey_auth:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail=f"Could not find user with hotkey: {hotkey}",
                    )
            logger.debug(f"Authenticated user: {user}")
            return user

    return _authenticate


# async def check_signature(
#     request: Request,
#     hotkey: str = Header(..., alias=HOTKEY_HEADER),
#     signature: str = Header(..., alias=SIGNATURE_HEADER),
#     nonce: str = Header(..., alias=NONCE_HEADER),
# ):
#     """Check the signature of the request is valid"""

#     body = await request.body()
#     body = body.decode()
#     message = get_signing_message(hotkey, nonce, body)
#     if nonce_is_valid(nonce):
#         keypair = Keypair(hotkey)
#         try:
#             logger.info(f"Verifying signature for message: {message}")
#             if keypair.verify(message, signature):
#                 return
#         except Exception as e:
#             logger.error(f"Error verifying signature: {e}")

#     raise HTTPException(
#         status_code=status.HTTP_401_UNAUTHORIZED,
#         detail=f"Invalid signature for key: {hotkey}",
#     )