from pathlib import Path

from main import FingerprintRegistry, MatchResult, build_redirect_url


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
