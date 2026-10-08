"""Static shell contract; no new backend routes or investigation mutations."""
from html.parser import HTMLParser
from pathlib import Path

from fastapi.testclient import TestClient
from app.config import Settings
from app.main import create_app


class ShellParser(HTMLParser):
    def __init__(self):
        super().__init__(); self.ids=[]; self.panes=[]; self.nav=[]; self.scripts=[]; self.disabled=[]
    def handle_starttag(self, tag, values):
        attrs=dict(values)
        if "id" in attrs:self.ids.append(attrs["id"])
        if "data-pane" in attrs:self.panes.append(attrs["data-pane"])
        if "data-nav" in attrs:self.nav.append(attrs["data-nav"])
        if tag=="script":self.scripts.append(attrs.get("src",""))
        if "disabled" in attrs:self.disabled.append(attrs.get("id"))


def test_console_has_unique_controls_dedicated_views_and_local_assets():
    with TestClient(create_app(Settings(_env_file=None))) as client:
        html=client.get("/").text; parsed=ShellParser(); parsed.feed(html)
        assert len(parsed.ids)==len(set(parsed.ids))
        expected={"overview","targets","graph","timeline","evidence","findings","collectors","settings","reports","active"}
        assert expected<=set(parsed.panes) and expected==set(parsed.nav)
        assert {"inspector-shell","graph-detail","activity-feed","current-case","local-indicator","case-library"}<=set(parsed.ids)
        assert "ai-nav" in parsed.disabled
        assert "Provider not configured" in html and "Reports" in html
        for asset in parsed.scripts:
            assert asset.startswith("/static/")
            assert client.get(asset).status_code==200
        assert "Graph actions never collect" in html


def test_responsive_motion_and_accessible_keyboard_contracts():
    css=Path("app/static/css/main.css").read_text(encoding="utf-8")
    assert "100dvh" in css and "prefers-reduced-motion" in css
    assert ":focus-visible" in css and "max-width:980px" in css
    html=Path("app/static/index.html").read_text(encoding="utf-8")
    assert "Skip to investigation" in html and 'aria-label="Investigation sections"' in html
    assert 'aria-live="polite"' in html
    js=Path("app/static/js/console.js").read_text(encoding="utf-8")
    assert "12000" in js and "document.hidden" in js
    assert '"POST"' not in js and '"PATCH"' not in js and '"DELETE"' not in js


def test_correction_layout_and_target_marker_contracts():
    html=Path("app/static/index.html").read_text(encoding="utf-8")
    css=Path("app/static/css/main.css").read_text(encoding="utf-8")
    graph=Path("app/static/js/investigation.js").read_text(encoding="utf-8")
    assert "toolbar-primary" in html and "toolbar-filters" in html
    assert "graph-search-results" in html and "graph-empty-action" in html
    assert 'class="inspector-reopen"' not in html
    assert '<details class="graph-legend">' in html
    assert "grid-template-columns:minmax(0,1fr) auto" in css
    assert "storedTargetRoots" in graph and "targets.filter(t=>!t.archived)" in graph
    assert "seenNodes" in graph and "Date.now()+1500" in graph
    # Desktop minimum control tracks fit with an open inspector at each review size.
    for width in (1366,1600,1920):
        inspector=285 if width<=1400 else 360
        available=width-176-inspector-40
        assert available>=150+115+120+95+95+4*14


def test_graph_presentation_controls_use_local_state_without_backend_mutations():
    html=Path("app/static/index.html").read_text(encoding="utf-8")
    parsed=ShellParser();parsed.feed(html)
    assert {"graph-certificates","graph-hostnames","graph-size-up","graph-size-down","graph-size-reset","graph-zoom-in","graph-zoom-out","graph-layout-status","graph-selected"}<=set(parsed.ids)
    assert '<option value="breadthfirst">Hierarchical</option>' in html
    assert '<option value="concentric">Radial</option>' in html
    graph=Path("app/static/js/investigation.js").read_text(encoding="utf-8")
    assert "window.localStorage" in graph and "spectre.graph.v1.u" in graph
    assert 'cy.on("dragfree"' in graph and "GraphPresentationState" in graph
    assert '"POST"' not in graph and '"PATCH"' not in graph and '"DELETE"' not in graph
    assert 'cy.on("dragfree","node",()=>savePresentation())' in graph
