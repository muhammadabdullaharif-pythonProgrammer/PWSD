"""Lexical & behavioural feature extractor for URLs.

Computes:
    * url_length
    * subdomain_count
    * shannon entropy
    * direct-IP usage flag
    * suspicious keyword occurrences (login / verify / secure / ...)
    * special character density
    * https / port / @-symbol indicators
"""
from __future__ import annotations
from math import log2
from urllib.parse import urlparse
import ipaddress
import re

SUSPICIOUS_KEYWORDS = (
    "login", "verify", "secure", "account", "update", "bank",
    "confirm", "signin", "password", "wallet", "payment", "free",
)
SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly")


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * log2(c / n) for c in freq.values())


def _is_direct_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def extract_features(url: str) -> dict:
    """Return a dict of numerical / boolean features for *url*."""
    url = (url or "").strip()
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""

    subdomain_count = max(0, host.count(".") - 1) if host else 0
    keyword_hits = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url.lower())
    specials = len(re.findall(r"[@\-_%?=&]", url))
    digits = sum(c.isdigit() for c in url)

    return {
        "url_length":          len(url),
        "host_length":         len(host),
        "path_length":         len(path),
        "subdomain_count":     subdomain_count,
        "entropy":             round(_shannon_entropy(url), 4),
        "uses_ip":             _is_direct_ip(host),
        "uses_https":          parsed.scheme == "https",
        "has_at_symbol":       "@" in url,
        "has_port":            bool(parsed.port),
        "is_shortener":        any(s in host for s in SHORTENERS),
        "suspicious_keywords": keyword_hits,
        "special_char_count":  specials,
        "digit_count":         digits,
    }
