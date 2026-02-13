from pathlib import Path
from unittest.mock import patch

from main import FingerprintRegistry, MatchResult, build_redirect_url, read_fingerprint_from_sensor


def test_new_fingerprint_routes_to_new_patient(tmp_path: Path) -> None:
    registry = FingerprintRegistry(tmp_path / "fingerprints.json")
    result = registry.identify_or_register("fingerprint-a")

    assert result == MatchResult(is_existing=False, patient_code="PAT00001")
    assert build_redirect_url("http://localhost:3000", result) == "http://localhost:3000/new-patient"


def test_existing_fingerprint_routes_with_code(tmp_path: Path) -> None:
    db = tmp_path / "fingerprints.json"
    registry = FingerprintRegistry(db)
    registry.identify_or_register("fingerprint-a")

    second_registry = FingerprintRegistry(db)
    existing = second_registry.identify_or_register("fingerprint-a")

    assert existing == MatchResult(is_existing=True, patient_code="PAT00001")
    assert (
        build_redirect_url("http://localhost:3000/", existing)
        == "http://localhost:3000/existing-patient?patient_code=PAT00001"
    )


def test_read_fingerprint_from_sensor_returns_capture_data() -> None:
    """When the WBF backend is mocked to return data, read_fingerprint_from_sensor returns it."""
    with patch("main._read_fingerprint_wbf", return_value="base64fingerprintdata"):
        assert read_fingerprint_from_sensor() == "base64fingerprintdata"


def test_read_fingerprint_from_sensor_falls_back_to_dpfpdd_when_wbf_fails(monkeypatch) -> None:
    """When backend is auto and WBF fails, dpfpdd is used."""
    monkeypatch.setenv("CP_FP_BACKEND", "auto")
    with patch("main._read_fingerprint_wbf", side_effect=RuntimeError("No WBF reader")):
        with patch("main._read_digitalpersona_uareu_fingerprint", return_value="dpfpdd-data"):
            assert read_fingerprint_from_sensor() == "dpfpdd-data"
