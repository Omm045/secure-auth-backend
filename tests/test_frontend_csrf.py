from pathlib import Path


def test_frontend_reset_fetches_and_sends_csrf_token():
    html = (Path(__file__).parents[1] / "frontend" / "app.js").read_text(encoding="utf-8")
    assert 'fetch("/csrf"' in html
    assert "X-CSRF-Token" in html
    assert '"/password/reset"' in html

def test_frontend_reset_reads_token_from_url():
    html = (Path(__file__).parents[1] / "frontend" / "reset.js").read_text(encoding="utf-8")
    assert 'URLSearchParams(window.location.hash.slice(1)).get("token")' in html
    page = (Path(__file__).parents[1] / "frontend" / "reset.html").read_text(encoding="utf-8")
    assert 'name="token" type="hidden"' in page
