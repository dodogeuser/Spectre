import re
from datetime import datetime

from app.collectors.base import Collector, CollectorResult
from app.collectors.domain_support import json_body, safe_parse
from app.collectors.providers import CertSpotter
from app.services.normalization import domain


def parse_ct(response, name):
    document = json_body(response)
    if not isinstance(document, list) or len(document) > 1000:
        raise ValueError("Invalid CT list")
    certificates = []
    for item in document[:100]:
        if not isinstance(item, dict) or not re.fullmatch(r"[0-9a-fA-F]{64}", item.get("cert_sha256", "")):
            raise ValueError("Invalid CT certificate fingerprint")
        names = item["dns_names"]
        if not isinstance(names, list) or len(names) > 500:
            raise ValueError("Invalid CT DNS names")
        observed = []
        wildcards = []
        for value in names:
            wildcard = isinstance(value, str) and value.startswith("*.")
            canonical = domain(value[2:] if wildcard else value)
            if canonical == name or canonical.endswith("." + name):
                (wildcards if wildcard else observed).append(canonical)
        if not observed and not wildcards:
            continue
        for field in ("not_before", "not_after"):
            if not isinstance(item[field], str):
                raise ValueError("Invalid certificate time")
            date = datetime.fromisoformat(item[field].replace("Z", "+00:00"))
            if date.tzinfo is None:
                raise ValueError("Certificate time must include offset")
        issuer = item.get("issuer", {}).get("friendly_name", "")
        if not isinstance(issuer, str) or len(issuer) > 500:
            raise ValueError("Invalid issuer")
        certificates.append({"sha256": item["cert_sha256"].lower(), "dns_names": sorted(set(observed)),
                             "wildcard_bases": sorted(set(wildcards)), "not_before": item["not_before"],
                             "not_after": item["not_after"], "issuer": issuer})
    if sum(len(item["dns_names"]) for item in certificates) > 1000:
        raise ValueError("CT normalized-name budget exceeded")
    return {"domain": name, "certificates": certificates, "coverage": "One provider page; up to 100 issuances, unexpired certificates only; not exhaustive."}


class CTCollector(Collector):
    name, version = "ct", "1.0.0"
    supported_types = frozenset({"domain"})

    def __init__(self, provider=None):
        self.provider = provider or CertSpotter()

    async def collect(self, target, context):
        name = domain(target.normalized_value)
        response = await self.provider.issuances(context.http, name)
        item, error = safe_parse(response, "ct", self.provider.name, lambda result: parse_ct(result, name))
        return CollectorResult(evidence=[item], status="failed" if error else "completed", error_code=error,
                               warnings=["CT observation unavailable (provider quota/authentication or malformed response)."] if error else ["One bounded CT page; wildcard names do not prove a concrete subdomain exists."])
