"""
Utility/helper functions.
"""

import re
import asyncio
import aiodns
import datetime
import hashlib
import random
import string
import time
import orjson as json
from typing import Set
from ipaddress import ip_address, IPv4Address, IPv6Address
from fastapi import status, HTTPException
from sqlalchemy import func
from sqlalchemy.future import select
from api.config import settings
from api.payment.schemas import Payment
from api.fmv.fetcher import get_fetcher
from api.permissions import Permissioning

ALLOWED_HOST_RE = re.compile(r"(?!-)[a-z\d-]{1,63}(?<!-)$")


def now_str():
    """
    Return current (UTC) timestamp as string.
    """
    return datetime.datetime.utcnow().isoformat()


def sse(data):
    """
    Format response object for server-side events stream.
    """
    return f"data: {json.dumps(data).decode()}\n\n"


def gen_random_token(k: int = 16) -> str:
    """
    Generate a random token, useful for fingerprints.
    """
    return "".join(random.sample(string.ascii_letters + string.digits, k=k))


def nonce_is_valid(nonce: str) -> bool:
    """Check if the nonce is valid."""
    return nonce and nonce.isdigit() and abs(time.time() - int(nonce)) < 600


def get_signing_message(
    hotkey: str,
    nonce: str,
    payload_str: str | bytes | None,
    purpose: str | None = None,
    payload_hash: str | None = None,
) -> str:
    """Get the signing message for a given hotkey, nonce, and payload."""
    if payload_str:
        if isinstance(payload_str, str):
            payload_str = payload_str.encode()
        return f"{hotkey}:{nonce}:{hashlib.sha256(payload_str).hexdigest()}"
    elif purpose:
        return f"{hotkey}:{nonce}:{purpose}"
    elif payload_hash:
        return f"{hotkey}:{nonce}:{payload_hash}"
    else:
        raise ValueError("Either payload_str or purpose must be provided")


def is_invalid_ip(ip: IPv4Address | IPv6Address) -> bool:
    """
    Check if IP address is private/local network.
    """
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


async def get_resolved_ips(host: str) -> Set[IPv4Address | IPv6Address]:
    """
    Resolve all IP addresses for a host.
    """
    resolver = aiodns.DNSResolver()
    resolved_ips = set()
    try:
        # IPv4
        try:
            result = await resolver.query(host, "A")
            for answer in result:
                resolved_ips.add(ip_address(answer.host))
        except aiodns.error.DNSError:
            pass

        # IPv6
        try:
            result = await resolver.query(host, "AAAA")
            for answer in result:
                resolved_ips.add(ip_address(answer.host))
        except aiodns.error.DNSError:
            pass
        if not resolved_ips:
            raise ValueError(f"Could not resolve any IP addresses for host: {host}")
        return resolved_ips
    except Exception as exc:
        raise ValueError(f"DNS resolution failed for host {host}: {str(exc)}")


async def is_valid_host(host: str) -> bool:
    """
    Validate host (IP or DNS name).
    """
    if not host or len(host) > 255:
        return False
    if not all(ALLOWED_HOST_RE.match(x) for x in host.lower().rstrip(".").split(".")):
        return False
    try:
        # IP address provided.
        addr = ip_address(host)
        return not is_invalid_ip(addr)
    except ValueError:
        # DNS hostname provided, look up IPs.
        try:
            resolved_ips = await asyncio.wait_for(get_resolved_ips(host), 5.0)
            return all(not is_invalid_ip(ip) for ip in resolved_ips)
        except ValueError:
            return False
    return False


async def ensure_is_developer(session, user):
    """
    Ensure a user is a developer, otherwise raise exception with helpful info.
    """
    if user.has_role(Permissioning.developer):
        return
    total_query = select(func.sum(Payment.usd_amount)).where(
        Payment.user_id == user.user_id, Payment.purpose == "developer"
    )
    total_payments = (await session.execute(total_query)).scalar() or 0
    fetcher = get_fetcher()
    fmv = await fetcher.get_price("tao")
    required_tao = (settings.developer_deposit - total_payments) / fmv
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=(
            "You do not have developer permissions, to enable developer permissions, "
            f"deposit ${settings.developer_deposit} USD worth of tao (currently ~{required_tao} tao) "
            f"to your developer deposit address: {user.developer_payment_address}"
        ),
    )
