from __future__ import annotations

from ipaddress import ip_address


def normalize_ip(value: str) -> str:
    return str(ip_address(value.strip()))


def is_public_ip(value: str) -> bool:
    ip = ip_address(value.strip())
    return ip.is_global
