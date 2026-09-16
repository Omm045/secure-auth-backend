from pathlib import Path


def test_frontend_reset_fetches_and_sends_csrf_token():
    html = (Path(__file__).parents[1] / "frontend" / "index.html").read_text(encoding="utf-8")
    assert "fetch('/csrf')" in html
    assert "X-CSRF-Token" in html
    assert "url==='/password/reset'" in html

def test_frontend_reset_reads_token_from_url():
    html = (Path(__file__).parents[1] / "frontend" / "reset.html").read_text(encoding="utf-8")
    assert "URLSearchParams(window.location.search).get('token')" in html
    assert "name=\"token\" type=\"hidden\"" in html
