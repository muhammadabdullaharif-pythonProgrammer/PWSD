"""Live network intelligence: WHOIS, DNS, and a Scapy-style packet trace.

All external calls are wrapped in defensive try/except so the platform
never surfaces a raw stack trace to the end user.
"""
from __future__ import annotations
from datetime import datetime, timezone
from urllib.parse import urlparse
import logging
import socket

logger = logging.getLogger(__name__)


def _host_of(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return (parsed.hostname or "").lower()


# ---------------------------------------------------------------------------
# WHOIS
# ---------------------------------------------------------------------------
def whois_lookup(url: str) -> dict:
    host = _host_of(url)
    out: dict = {"host": host, "error": None}
    if not host:
        out["error"] = "Invalid host"
        return out
    try:
        import whois  # python-whois
        data = whois.whois(host)
        created = data.creation_date
        if isinstance(created, list):
            created = created[0]
        expires = data.expiration_date
        if isinstance(expires, list):
            expires = expires[0]
        age_days = None
        if isinstance(created, datetime):
            now = datetime.now(timezone.utc) if created.tzinfo else datetime.utcnow()
            age_days = (now - created).days
        out.update({
            "registrar":   getattr(data, "registrar", None),
            "country":     getattr(data, "country", None),
            "creation":    str(created) if created else None,
            "expiration":  str(expires) if expires else None,
            "age_days":    age_days,
        })
    except Exception as exc:  # noqa: BLE001
        logger.warning("WHOIS failed for %s: %s", host, exc)
        out["error"] = "WHOIS lookup unavailable"
    return out


# ---------------------------------------------------------------------------
# DNS (A / MX / NS)
# ---------------------------------------------------------------------------
def dns_lookup(url: str) -> dict:
    host = _host_of(url)
    out: dict = {"host": host, "A": [], "MX": [], "NS": [], "error": None}
    if not host:
        out["error"] = "Invalid host"
        return out
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 4.0
        for rtype in ("A", "MX", "NS"):
            try:
                answers = resolver.resolve(host, rtype)
                out[rtype] = [str(a.to_text()) for a in answers]
            except Exception as exc:  # noqa: BLE001
                logger.info("DNS %s for %s failed: %s", rtype, host, exc)
                out[rtype] = []
    except Exception as exc:  # noqa: BLE001
        logger.warning("DNS resolver init failed: %s", exc)
        out["error"] = "DNS resolution unavailable"
    return out


# ---------------------------------------------------------------------------
# Scapy-style passive packet trace (simulated, safe & deterministic)
# ---------------------------------------------------------------------------
def packet_trace(url: str, hops: int = 5) -> list[dict]:
    """Return a synthetic but realistic packet-trace log.

    A real-world deployment would attach Scapy here; for portability we
    derive deterministic synthetic hops from the resolved IP.
    """
    host = _host_of(url)
    try:
        ip = socket.gethostbyname(host) if host else "0.0.0.0"
    except Exception:  # noqa: BLE001
        ip = "0.0.0.0"
    trace = []
    for i in range(1, hops + 1):
        trace.append({
            "hop": i,
            "ttl": 64 - i,
            "src": "192.168.1.10",
            "dst": ip,
            "proto": "TCP" if i % 2 else "UDP",
            "latency_ms": 8 + i * 4,
        })
    return trace


def analyse(url: str) -> dict:
    """Aggregate all network checks into one dict."""
    return {
        "whois":  whois_lookup(url),
        "dns":    dns_lookup(url),
        "trace":  packet_trace(url),
    }
