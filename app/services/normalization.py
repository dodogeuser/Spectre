"""Pure target validation and normalization. Never resolves or fetches targets."""
import ipaddress
import re
import unicodedata
from urllib.parse import urlsplit, urlunsplit

import idna

TARGET_TYPES = {"domain", "ipv4", "ipv6", "url", "organization", "username", "email"}


def domain(value: str) -> str:
    value = value.removesuffix(".")
    if value.endswith("."):
        raise ValueError("Invalid domain")
    try:
        result = idna.encode(value, uts46=True, std3_rules=True).decode("ascii").lower()
    except idna.IDNAError as exc:
        raise ValueError("Invalid domain") from exc
    if len(result) > 253 or "." not in result:
        raise ValueError("Domain must contain a valid DNS suffix")
    try:
        ipaddress.ip_address(result)
    except ValueError:
        return result
    raise ValueError("Use an IP target type for IP addresses")


def normalize(target_type: str, value: str) -> tuple[str, str]:
    if target_type not in TARGET_TYPES:
        raise ValueError("Unsupported target type")
    if any(unicodedata.category(char).startswith("C") for char in value):
        raise ValueError("Control and invisible formatting characters are not permitted")
    display = unicodedata.normalize("NFC", value.strip())
    if not display or len(display) > 2048:
        raise ValueError("Target must contain 1–2048 characters")
    if target_type == "domain":
        canonical = domain(display)
    elif target_type in {"ipv4", "ipv6"}:
        if "%" in display:
            raise ValueError("Scoped IPv6 addresses are not supported")
        try:
            address = ipaddress.ip_address(display)
        except ValueError as exc:
            raise ValueError("Invalid IP address") from exc
        if address.version != (4 if target_type == "ipv4" else 6):
            raise ValueError("IP address does not match target type")
        canonical = address.compressed
    elif target_type == "url":
        if "\\" in display or re.search(r"\s", display) or re.search(r"%(?![0-9a-fA-F]{2})", display):
            raise ValueError("Invalid URL characters")
        try:
            parts = urlsplit(display)
            if parts.scheme.lower() not in {"http", "https"} or not parts.hostname or parts.username is not None or parts.password is not None:
                raise ValueError("Only absolute HTTP/HTTPS URLs without credentials are supported")
            port = parts.port
            if port == 0:
                raise ValueError("Invalid URL port")
            host = parts.hostname
            if "%" in host:
                raise ValueError("Invalid URL host")
            try:
                address = ipaddress.ip_address(host)
                host = f"[{address.compressed}]" if address.version == 6 else address.compressed
            except ValueError:
                host = domain(host)
            scheme = parts.scheme.lower()
            if port is not None and port != (443 if scheme == "https" else 80):
                host += f":{port}"
            canonical = urlunsplit((scheme, host, parts.path or "/", parts.query, ""))
        except ValueError as exc:
            raise ValueError("Invalid public URL syntax") from exc
        if not canonical.isascii():
            raise ValueError("Encode non-ASCII URL paths and queries with percent encoding")
    elif target_type == "email":
        if display.count("@") != 1:
            raise ValueError("Invalid email address")
        local, host = display.rsplit("@", 1)
        if len(local) > 64 or not re.fullmatch(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+", local) or local.startswith(".") or local.endswith(".") or ".." in local:
            raise ValueError("Only unquoted ASCII email local parts are supported")
        canonical = local + "@" + domain(host)
        if len(canonical) > 254:
            raise ValueError("Email address is too long")
    elif target_type == "organization":
        display = " ".join(display.split())
        canonical = display.casefold()
    else:
        if re.search(r"\s", display):
            raise ValueError("Username must not contain whitespace")
        canonical = display  # Platform-specific case rules cannot be assumed.
    return display, canonical
