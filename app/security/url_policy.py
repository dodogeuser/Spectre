"""Fail-closed URL and destination validation. No private-network exceptions."""
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import idna


class NetworkPolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Destination:
    url: str
    scheme: str
    host: str
    port: int
    path: str
    accept: str = "application/json,text/plain,text/html"


def public_address(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise NetworkPolicyError("Invalid destination address") from exc
    # is_global alone includes multicast on some Python versions.
    if not address.is_global or address.is_multicast or address.is_reserved or address.is_unspecified or str(address) == "168.63.129.16":
        raise NetworkPolicyError("Non-public destination blocked")
    if isinstance(address, ipaddress.IPv6Address) and (address.ipv4_mapped or address.sixtofour or address.teredo):
        raise NetworkPolicyError("IPv6 transition addresses blocked")
    return address.compressed


def validate_url(url: str) -> Destination:
    if len(url) > 4096 or not url.isascii() or any(ord(char) <= 32 or ord(char) == 127 for char in url) or "\\" in url:
        raise NetworkPolicyError("Invalid outbound URL")
    try:
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname or parts.username is not None or parts.password is not None:
            raise NetworkPolicyError("Only credential-free HTTPS is permitted")
        host = parts.hostname.rstrip(".").lower()
        if "%" in host or host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
            raise NetworkPolicyError("Local destination blocked")
        port = parts.port if parts.port is not None else 443
        if port != 443:
            raise NetworkPolicyError("Only HTTPS port 443 is permitted")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            host = idna.encode(host, uts46=True, std3_rules=True).decode("ascii")
            if "." not in host:
                raise NetworkPolicyError("Fully qualified hostname required")
        else:
            public_address(host)
        authority = f"[{host}]" if ":" in host else host
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        canonical = urlunsplit(("https", authority, parts.path or "/", parts.query, ""))
        return Destination(canonical, "https", host, port, path)
    except (ValueError, idna.IDNAError) as exc:
        raise NetworkPolicyError("Invalid or prohibited outbound URL") from exc


def resolve_public(host: str, port: int) -> tuple[str, ...]:
    answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not answers:
        raise NetworkPolicyError("Destination has no addresses")
    # Reject mixed public/private answers, not merely the selected address.
    return tuple(dict.fromkeys(public_address(answer[4][0]) for answer in answers))
