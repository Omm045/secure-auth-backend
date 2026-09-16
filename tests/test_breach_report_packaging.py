from pathlib import Path


def test_synthetic_breach_fixture_is_packaged_with_application():
    fixture = Path(__file__).parents[1] / "app" / "data" / "sample_accounts.csv"
    assert fixture.is_file()
    assert "example.test" in fixture.read_text(encoding="utf-8")
