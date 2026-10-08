"""Replaceable adapters; every request uses the injected controlled HTTP client."""
import base64
from urllib.parse import urlencode

import dns.message


class CloudflareDNS:
    name = "Cloudflare DoH"
    endpoint = "https://cloudflare-dns.com/dns-query"

    async def query(self, client, name, record_type):
        query = dns.message.make_query(name, record_type)
        query.id = 0
        wire = query.to_wire()
        encoded = base64.urlsafe_b64encode(wire).decode("ascii").rstrip("=")
        response = await client.get(self.endpoint + "?" + urlencode({"dns": encoded}), accept="application/dns-message")
        return query, response


class IanaRDAP:
    name = "IANA bootstrap / authoritative RDAP"
    bootstrap = "https://data.iana.org/rdap/dns.json"

    async def discover(self, client):
        return await client.get(self.bootstrap)

    async def lookup(self, client, base, name):
        # Base is selected only from validated IANA bootstrap data, not caller input.
        return await client.get(base.rstrip("/") + "/domain/" + name, accept="application/rdap+json")


class CertSpotter:
    name = "SSLMate Cert Spotter CT Search API v1"
    endpoint = "https://api.certspotter.com/v1/issuances"

    async def issuances(self, client, name):
        query = urlencode([("domain", name), ("include_subdomains", "true"), ("expand", "dns_names"), ("expand", "issuer")])
        return await client.get(self.endpoint + "?" + query, host_interval=60)
