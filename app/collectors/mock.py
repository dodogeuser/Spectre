from app.collectors.base import Collector, CollectorResult, EvidenceItem


class MockCollector(Collector):
    name = "mock"
    version = "1.0.0"
    supported_types = frozenset({"domain", "ipv4", "ipv6", "url", "organization", "username", "email"})

    async def collect(self, target, context):
        return CollectorResult(evidence=[EvidenceItem(
            source_type="synthetic", source_ref=f"mock://target/{target.id}",
            raw_json={"synthetic": True, "target_type": target.type, "value": target.normalized_value},
            parsed_json={"synthetic": True, "observations": []},
        )], warnings=["Synthetic framework test only; no intelligence collected."])
