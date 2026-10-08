"""Active-only exact-host policy. Passive outbound policy is unchanged."""
import ipaddress
import re
from typing import Literal
from urllib.parse import unquote, urlsplit, urlencode

from pydantic import BaseModel, ConfigDict, Field, field_validator
from fastapi import HTTPException
from app.security.url_policy import Destination, NetworkPolicyError, validate_url

PORTS=frozenset({80,443})
SENSITIVE=re.compile(r"(?i)auth|cookie|token|secret|password|passwd|api.?key|credential|session")


class RunOptions(BaseModel):
    model_config=ConfigDict(extra="forbid")
    module: Literal['http','tls','service','validation','manual']
    method: Literal['GET','HEAD','OPTIONS']='HEAD'
    scheme: Literal['http','https']='https'
    path: str=Field(default='/',max_length=512)
    query: dict[str,str]=Field(default_factory=dict,max_length=8)
    headers: dict[str,str]=Field(default_factory=dict,max_length=2)
    ports: list[Literal[80,443]]=Field(default_factory=lambda:[443],min_length=1,max_length=2)
    finding_id: int|None=Field(default=None,gt=0)
    confirmed: Literal[True]

    @field_validator('path')
    @classmethod
    def safe_path(cls,value):
        decoded=unquote(unquote(value))
        if not value.isascii() or not decoded.isascii() or not decoded.startswith('/') or decoded.startswith('//') or any(c in decoded for c in ('\\','?','#','@',':','%')) or any(ord(c)<=32 or ord(c)==127 for c in decoded) or '..' in decoded.split('/'):
            raise ValueError('One literal host-bound path is required')
        return value

    @field_validator('query')
    @classmethod
    def safe_query(cls,value):
        if any(not re.fullmatch(r'[a-zA-Z0-9_-]{1,40}',key) or SENSITIVE.search(key) or len(item)>128 or not item.isascii() or any(ord(c)<32 or ord(c)==127 for c in item) or SENSITIVE.search(item) or '://' in item for key,item in value.items()):
            raise ValueError('Sensitive or invalid query parameters are prohibited')
        return value

    @field_validator('headers')
    @classmethod
    def safe_headers(cls,value):
        if any(key.lower() not in {'accept','accept-language'} or not item.isascii() or len(item)>256 or any(ord(c)<32 or ord(c)==127 for c in item) or SENSITIVE.search(item) for key,item in value.items()):
            raise ValueError('Only bounded non-sensitive Accept/Accept-Language headers are allowed')
        return {key.lower():item for key,item in value.items()}


def target_host(target):
    if target.type=='domain':host=target.normalized_value
    elif target.type=='url':host=urlsplit(target.normalized_value).hostname
    else:raise HTTPException(422,'Active verification requires an explicitly authorized domain or URL target')
    validate_url('https://'+host+'/')
    try:ipaddress.ip_address(host)
    except ValueError:return host
    raise HTTPException(422,'Active verification binds to a DNS host, not an IP/CIDR target')


def destination(url,host,ports):
    if len(url)>2048 or not url.isascii() or '\\' in url or any(ord(c)<=32 or ord(c)==127 for c in url):
        raise NetworkPolicyError('Invalid active destination')
    try:
        parts=urlsplit(url)
        if parts.hostname!=host or parts.username is not None or parts.password is not None or parts.fragment:
            raise NetworkPolicyError('Destination leaves exact authorized host')
        port=parts.port if parts.port is not None else (443 if parts.scheme=='https' else 80)
        if (parts.scheme,port) not in {('https',443),('http',80)} or port not in ports:
            raise NetworkPolicyError('Destination leaves authorized web ports')
        # Reuse canonical host/local/private-literal checks without weakening HTTPS-only passive policy.
        validate_url('https://'+host+(parts.path or '/')+('?' + parts.query if parts.query else ''))
        path=(parts.path or '/')+('?' + parts.query if parts.query else '')
        return Destination(url,parts.scheme,host,port,path)
    except ValueError as exc:raise NetworkPolicyError('Invalid active destination') from exc


def request_url(host,options):
    return f'{options.scheme}://{host}{options.path}'+('?' + urlencode(options.query) if options.query else '')
