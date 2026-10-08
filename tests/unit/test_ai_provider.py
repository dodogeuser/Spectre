import json
from unittest.mock import patch

import httpx
import pytest

from app.ai.provider import OllamaProvider, ProviderError
from app.config import Settings


def test_disabled_provider_does_not_contact_network():
    provider = OllamaProvider(Settings(_env_file=None))
    with patch("httpx.Client", side_effect=AssertionError("No connection")), pytest.raises(ProviderError) as exc:
        provider.answer("question", {})
    assert exc.value.code == "not_configured"


@pytest.mark.parametrize("scenario", ["success", "timeout", "failure", "redirect", "tool", "malformed", "oversize"])
def test_literal_local_transport_no_tools_proxies_or_redirects(scenario):
    provider = OllamaProvider(Settings(_env_file=None, ai_enabled=True, ai_model="local-test-model"))
    def handler(request):
        assert str(request.url) in ("http://127.0.0.1:11434/api/show", "http://127.0.0.1:11434/api/chat")
        value = json.loads(request.content)
        if request.url.path == "/api/show":
            assert set(value) == {"model"}
            return httpx.Response(200, json={"details": {"format": "gguf"}})
        assert value["stream"] is False and "tools" not in value
        assert len(value["messages"]) == 2 and value["messages"][0]["role"] == "system"
        if scenario == "timeout": raise httpx.ReadTimeout("timeout")
        if scenario == "failure": return httpx.Response(500)
        if scenario == "redirect": return httpx.Response(302, headers={"Location": "https://evil.example"})
        if scenario == "malformed": return httpx.Response(200, text="not json")
        if scenario == "oversize": return httpx.Response(200, text="x"*65537)
        message = {"content": json.dumps({"insufficient": True, "selections": []})}
        if scenario == "tool": message["tool_calls"] = [{"function": {"name": "scan"}}]
        return httpx.Response(200, json={"done": True, "message": message})
    original = httpx.Client
    def client(**kwargs):
        assert kwargs["trust_env"] is False and kwargs["follow_redirects"] is False
        return original(**kwargs, transport=httpx.MockTransport(handler))
    with patch("app.ai.provider.httpx.Client", side_effect=client):
        if scenario == "success": assert provider.answer("question", {})["insufficient"] is True
        else:
            with pytest.raises(ProviderError): provider.answer("question", {})
    assert provider._admission.acquire(blocking=False); provider._admission.release()


def test_cloud_alias_never_receives_case_context():
    provider = OllamaProvider(Settings(_env_file=None, ai_enabled=True, ai_model="test-cloud"))
    with patch("httpx.Client", side_effect=AssertionError("No request")), pytest.raises(ProviderError) as exc:
        provider.answer("question", {"private": "case"})
    assert exc.value.code == "local_model_required"


def test_remote_model_metadata_prevents_prompt_transmission():
    provider = OllamaProvider(Settings(_env_file=None, ai_enabled=True, ai_model="innocent-alias"))
    def handler(request):
        assert request.url.path == "/api/show"
        assert "private" not in request.content.decode()
        return httpx.Response(200, json={"remote_host": "https://ollama.com", "details": {"format": "gguf"}})
    original = httpx.Client
    with patch("app.ai.provider.httpx.Client", side_effect=lambda **kwargs: original(**kwargs, transport=httpx.MockTransport(handler))), pytest.raises(ProviderError):
        provider.answer("question", {"private": "case"})
