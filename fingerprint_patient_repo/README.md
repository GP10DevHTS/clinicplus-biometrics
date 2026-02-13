# Fingerprint Patient Router

This folder contains a standalone Python project that:

1. Captures fingerprint input.
2. Checks whether the fingerprint already exists in a local registry.
3. Opens ClinicPlus in the browser to:
   - `.../new-patient` for a new fingerprint.
   - `.../existing-patient?patient_code=...` for an existing fingerprint.

---

## 1) Prerequisites

- Python 3.10+
- A running ClinicPlus web app (for example on `http://localhost:8000`)
- A DigitalPersona fingerprint scanner connected to the machine
- DigitalPersona runtime/driver installed and scanner visible in Device Manager (Windows) or equivalent OS tooling

> **Important**
> `main.py` now contains a concrete DigitalPersona U.are.U SDK capture implementation via `ctypes` and `dpfpdd.dll`.
> For local testing without hardware, set `CP_FP_MOCK_DATA` to bypass scanner capture.

---

## 2) Install

```bash
cd fingerprint_patient_repo
python3 -m venv .venv
source .venv/bin/activate   # Windows PowerShell: .venv\Scripts\Activate.ps1
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements-dev.txt
```

---

## 3) Configure ClinicPlus Routing

The script accepts two runtime options:

- `--base-url`: ClinicPlus app base URL (default: `http://localhost:8000`)
- `--db`: local fingerprint registry JSON file (default: `./data/fingerprints.json`)

Example:

```bash
python3 main.py --base-url http://localhost:8000 --db ./data/fingerprints.json
```

Routing behavior:

- New fingerprint: opens `http://localhost:8000/new-patient`
- Existing fingerprint: opens `http://localhost:8000/existing-patient?patient_code=PATxxxxx`

Make sure ClinicPlus has routes/pages that accept:

- `/new-patient`
- `/existing-patient?patient_code=<code>`

---

## 4) Configure DigitalPersona Integration (Implementation Guide)

DigitalPersona SDKs vary by OS/version and are often distributed with vendor docs. Use this integration pattern:

1. Install the DigitalPersona SDK/runtime and verify scanner capture works with vendor sample tools.
2. Confirm `dpfpdd.dll` is accessible from PATH (or same directory as the Python process).
3. `main.py` calls the SDK functions `dpfpdd_init`, `dpfpdd_query_devices`, `dpfpdd_open`, and `dpfpdd_capture` to capture one sample.
4. Captured bytes are base64 encoded and then hashed by `FingerprintRegistry` (SHA-256) before storage.
5. Run the script and validate:
   - first scan routes to `/new-patient`
   - repeat scan routes to `/existing-patient?patient_code=...`

### Suggested function contract

`read_fingerprint_from_sensor()` behavior in this project:

- uses `CP_FP_MOCK_DATA` when present (useful for local/dev testing),
- otherwise performs a real scanner capture through DigitalPersona SDK,
- raises explicit runtime errors when reader/runtime is unavailable.

---

## 5) Run Tests

```bash
cd fingerprint_patient_repo
python3 -m pytest -q
```

---

## 6) ClinicPlus Integration Notes

- If ClinicPlus expects a different query parameter (for example `patientCode` instead of `patient_code`), update `build_redirect_url()` in `main.py`.
- Patient codes are generated sequentially as `PAT00001`, `PAT00002`, ... based on current registry size.
- Registry is local JSON for demo/prototype use. For production, move to a secure backend database and add concurrency controls.

---

## 7) Security and Compliance Notes

- Fingerprint information is sensitive biometric data.
- This sample hashes fingerprint templates before persistence, but production deployments should also include:
  - encrypted at-rest storage,
  - strict access controls,
  - audit logging,
  - retention/deletion policies,
  - legal/compliance review (HIPAA/local biometric laws as applicable).


## 8) C++ Version (DigitalPersona/WBF)

A C++ implementation is now available at `fingerprint_patient_repo/cpp/main.cpp`.
It follows the same routing flow as the Python app and uses the same SDK pattern from the DigitalPersona guide:

- `WinBio*` API path for WBF-compatible readers (`--backend wbf`)
- `dpfpdd.dll` path for DigitalPersona U.are.U SDK readers (`--backend dpfpdd`)
- `auto` mode tries WBF first and falls back to `dpfpdd`

### Build

```bash
cd fingerprint_patient_repo/cpp
cmake -S . -B build
cmake --build build
```

### Run

```bash
# For hardware capture on Windows (with drivers/runtime)
./build/fingerprint_router --base-url http://localhost:3000 --db ./data/fingerprints_cpp.tsv --backend auto

# For local testing without scanner
CP_FP_MOCK_DATA=test-fingerprint ./build/fingerprint_router --base-url http://localhost:3000
```

Notes:
- The C++ version currently persists hash->patient mappings in a TSV file (`fingerprints_cpp.tsv`).
- On non-Windows platforms, fingerprint capture is not implemented; use `CP_FP_MOCK_DATA` for dry runs.

