# Fingerprint Patient Router (New Repo Scaffold)

This folder contains a standalone Python project that:

1. Reads a fingerprint sample from a scanner input (currently mocked with terminal input).
2. Checks whether the fingerprint already exists in a local JSON registry.
3. Opens the browser to:
   - `.../new-patient` when the fingerprint is new.
   - `.../existing-patient?patient_code=...` when the fingerprint already exists.

## Run

```bash
cd fingerprint_patient_repo
python3 main.py --base-url http://localhost:3000 --db ./data/fingerprints.json
```

## Test

```bash
cd fingerprint_patient_repo
python3 -m pytest -q
```

## Notes

- Replace `read_fingerprint_from_sensor()` with your real scanner SDK logic.
- Fingerprints are SHA-256 hashed before storing.
