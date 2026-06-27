import requests
import time
import threading
from collections import OrderedDict

_cache = OrderedDict()
_cache_lock = threading.Lock()
_MAX_CACHE = 2000
_PRIVATE_RANGES = [
    ("10.", 8), ("172.16.", 12), ("172.17.", 12), ("172.18.", 12),
    ("172.19.", 12), ("172.20.", 12), ("172.21.", 12), ("172.22.", 12),
    ("172.23.", 12), ("172.24.", 12), ("172.25.", 12), ("172.26.", 12),
    ("172.27.", 12), ("172.28.", 12), ("172.29.", 12), ("172.30.", 12),
    ("172.31.", 12), ("192.168.", 16), ("127.", 8), ("169.254.", 16),
    ("::1", 0), ("fc", 0), ("fd", 0),
]


def _is_private(ip: str) -> bool:
    for prefix, _ in _PRIVATE_RANGES:
        if ip.startswith(prefix):
            return True
    return False


def _geo_result(ip, data=None):
    if data is None:
        return {"ip": ip, "country": "Private", "countryCode": "--", "city": "—",
                "lat": 0.0, "lon": 0.0, "isp": "—", "org": "—", "private": True}
    return {
        "ip": ip,
        "country": data.get("country", "Unknown"),
        "countryCode": data.get("countryCode", "??"),
        "city": data.get("city", "Unknown"),
        "lat": data.get("lat", 0.0),
        "lon": data.get("lon", 0.0),
        "isp": data.get("isp", "Unknown"),
        "org": data.get("org", ""),
        "private": False,
    }


def geolocate(ip: str) -> dict:
    if _is_private(ip):
        return _geo_result(ip)

    with _cache_lock:
        if ip in _cache:
            return _cache[ip]

    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,city,lat,lon,isp,org"},
            timeout=4,
        )
        data = r.json()
        result = _geo_result(ip, data if data.get("status") == "success" else None)
    except Exception:
        result = _geo_result(ip, None)
        result["country"] = "Unknown"
        result["private"] = False

    with _cache_lock:
        if len(_cache) >= _MAX_CACHE:
            _cache.popitem(last=False)
        _cache[ip] = result

    return result


def geolocate_batch(ips: list[str], delay: float = 0.07) -> dict[str, dict]:
    """Geolocate a list of IPs with rate limiting (ip-api.com allows 45 req/min free)."""
    results = {}
    to_fetch = []

    with _cache_lock:
        for ip in ips:
            if ip in _cache:
                results[ip] = _cache[ip]
            elif _is_private(ip):
                results[ip] = _geo_result(ip)
            else:
                to_fetch.append(ip)

    for ip in to_fetch:
        results[ip] = geolocate(ip)
        if delay:
            time.sleep(delay)

    return results
