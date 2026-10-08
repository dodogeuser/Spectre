"""Approved source preservation, compact local assets and release inclusion."""
import hashlib
from pathlib import Path
from PIL import Image
from scripts.release_package import files

ROOT=Path(__file__).resolve().parents[2]
BRAND=ROOT/'app/static/images/branding'

def test_approved_branding_assets_and_release_payload():
    assert hashlib.sha256((BRAND/'spectre-logo.png').read_bytes()).hexdigest()=='c2f244ff5fece786f2ca54d3755b92cc76ac066288efd1ed0b94cfe39e3bd6a0'
    included=set(files(ROOT))
    for name,width in [('spectre-ui.png',96),('spectre-display.png',256),('spectre-report.png',128)]:
        asset=BRAND/name
        with Image.open(asset) as im:
            assert im.width==width and abs(im.width/im.height-1289/1221)<.01
        assert asset.stat().st_size<80000 and asset in included
    for size in (16,32,180):
        asset=BRAND/f'favicon-{size}.png'
        with Image.open(asset) as im:assert im.size==(size,size)
        assert asset in included
    with Image.open(BRAND/'favicon.ico') as im:
        assert im.ico.sizes()=={(16,16),(32,32),(48,48),(64,64)}
    assert BRAND/'spectre-logo.png' in included
    assert BRAND/'favicon.ico' in included
    markup=(ROOT/'app/static/index.html').read_text(encoding='utf-8')
    assert '/static/images/branding/spectre-display.png' in markup
    assert '/static/images/branding/spectre-ui.png' in markup
    assert 'sizes="32x32"' in markup and 'sizes="16x16"' in markup
    assert 'app/static/images/branding/spectre-display.png' in (ROOT/'README.md').read_text(encoding='utf-8')
