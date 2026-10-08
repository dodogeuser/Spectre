"""Replaceable passive IP provider contracts; no adapter owns a transport."""
from typing import Protocol
from urllib.parse import urlencode

from app.collectors.providers import CloudflareDNS
from app.services.http_client import ControlledHttpClient, HttpResult


class ReverseDNSProvider(Protocol):
    name: str
    async def query(self, client: ControlledHttpClient, name: str, record_type: str): ...


class NetworkRDAPProvider(Protocol):
    name: str
    async def discover(self, client: ControlledHttpClient, version: int) -> HttpResult: ...
    async def lookup(self, client: ControlledHttpClient, base: str, address: str) -> HttpResult: ...


class RoutingProvider(Protocol):
    name: str
    async def network(self, client: ControlledHttpClient, address: str) -> HttpResult: ...
    async def overview(self, client: ControlledHttpClient, prefix: str) -> HttpResult: ...


class IanaNetworkRDAP:
    name = "IANA IP bootstrap / authoritative network RDAP"

    async def discover(self, client, version):
        return await client.get(f"https://data.iana.org/rdap/ipv{version}.json")

    async def lookup(self, client, base, address):
        return await client.get(base.rstrip("/") + "/ip/" + address, accept="application/rdap+json")


class RIPEstatRouting:
    name = "RIPE NCC RIPEstat / RIS routing observations"
    endpoint = "https://stat.ripe.net/data/"

    async def network(self, client, address):
        return await client.get(self.endpoint + "network-info/data.json?" + urlencode({"resource": address}), host_interval=2)

    async def overview(self, client, prefix):
        return await client.get(self.endpoint + "prefix-overview/data.json?" + urlencode({"resource": prefix, "max_related": 0}), host_interval=2)


DefaultReverseDNS = CloudflareDNS
