from __future__ import annotations

import argparse
import hashlib
import json
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Dict
from urllib.parse import urlencode


@dataclass
class MatchResult:
    is_existing: bool
    patient_code: str


class FingerprintRegistry:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._records: Dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        if self.db_path.exists():
            self._records = json.loads(self.db_path.read_text(encoding="utf-8"))
        else:
            self._records = {}

    def _save(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db_path.write_text(json.dumps(self._records, indent=2), encoding="utf-8")

    @staticmethod
    def _hash_fingerprint(fingerprint_data: str) -> str:
        return hashlib.sha256(fingerprint_data.encode("utf-8")).hexdigest()

    def identify_or_register(self, fingerprint_data: str) -> MatchResult:
        fingerprint_hash = self._hash_fingerprint(fingerprint_data)

        if fingerprint_hash in self._records:
            return MatchResult(is_existing=True, patient_code=self._records[fingerprint_hash])

        patient_code = self._next_patient_code()
        self._records[fingerprint_hash] = patient_code
        self._save()
        return MatchResult(is_existing=False, patient_code=patient_code)

    def _next_patient_code(self) -> str:
        latest = len(self._records) + 1
        return f"PAT{latest:05d}"


def build_redirect_url(base_url: str, result: MatchResult) -> str:
    base_url = base_url.rstrip("/")

    if result.is_existing:
        query = urlencode({"patient_code": result.patient_code})
        return f"{base_url}/existing-patient?{query}"

    return f"{base_url}/new-patient"


def read_fingerprint_from_sensor() -> str:
    # Replace this mock input with real sensor SDK integration.
    return input("Scan fingerprint (enter sample text/id): ").strip()


def main() -> None:
    parser = argparse.ArgumentParser(description="Fingerprint to patient routing")
    parser.add_argument(
        "--base-url",
        default="http://localhost:3000",
        help="Web app base URL",
    )
    parser.add_argument(
        "--db",
        default="./data/fingerprints.json",
        help="Fingerprint DB JSON path",
    )
    args = parser.parse_args()

    fingerprint_data = read_fingerprint_from_sensor()
    if not fingerprint_data:
        raise ValueError("No fingerprint data was captured.")

    registry = FingerprintRegistry(Path(args.db))
    result = registry.identify_or_register(fingerprint_data)
    url = build_redirect_url(args.base_url, result)

    print(f"Matched existing patient: {result.is_existing}")
    print(f"Patient code: {result.patient_code}")
    print(f"Opening: {url}")
    webbrowser.open(url)


if __name__ == "__main__":
    main()
