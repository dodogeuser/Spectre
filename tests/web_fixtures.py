from pathlib import Path
from app.services.http_client import HttpResult


class WebFixtureHTTP:
    def __init__(self, status=200, body=None, content_type="text/html; charset=utf-8", error=None):
        self.status, self.body, self.content_type, self.error = status, body, content_type, error
        self.calls = []
    async def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if self.error:
            raise self.error
        body = self.body if self.body is not None else (Path(__file__).parent / "fixtures/web_page.html").read_bytes()
        return HttpResult(url, {"status": self.status, "headers": {"content-type": self.content_type, "server": "fixture hint", "x-content-type-options": "nosniff"}, "synthetic_fixture": True}, body)
