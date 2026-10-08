import re
from types import MappingProxyType

from app.collectors.base import Collector
from app.collectors.mock import MockCollector
from app.collectors.dns import DNSCollector
from app.collectors.rdap import RDAPCollector
from app.collectors.ct import CTCollector
from app.collectors.ip_intelligence import ReverseDNSCollector, NetworkRDAPCollector, ASNCollector
from app.collectors.web_metadata import WebMetadataCollector
from app.services.normalization import TARGET_TYPES


class CollectorRegistry:
    def __init__(self, collectors: tuple[Collector, ...], disabled: frozenset[str] = frozenset()):
        entries = {}
        for collector in collectors:
            if not re.fullmatch(r"[a-z][a-z0-9_]{0,49}", collector.name) or collector.name in entries:
                raise ValueError("Invalid or duplicate collector name")
            if not collector.version or len(collector.version) > 50 or not collector.supported_types or not collector.supported_types <= TARGET_TYPES:
                raise ValueError("Invalid collector contract")
            if not collector.passive:
                raise ValueError("Active collectors are not supported in Phase 03")
            entries[collector.name] = collector
        self.entries = MappingProxyType(entries)
        self.disabled = disabled

    def get(self, name: str) -> Collector:
        if name in self.disabled or name not in self.entries:
            raise KeyError(name)
        return self.entries[name]


def default_registry(settings=None):
    disabled = frozenset(name for name in ("dns", "rdap", "ct", "reverse_dns", "ip_rdap", "ip_asn", "web_metadata") if settings is not None and not getattr(settings, name + "_enabled"))
    return CollectorRegistry((MockCollector(), DNSCollector(), RDAPCollector(), CTCollector(), ReverseDNSCollector(), NetworkRDAPCollector(), ASNCollector(), WebMetadataCollector()), disabled)
