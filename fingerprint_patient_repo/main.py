from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import json
import os
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


class DPFPDD_DEV(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char * 1024),
        ("priority", ctypes.c_uint),
        ("modality", ctypes.c_uint),
        ("technology", ctypes.c_uint),
    ]


class DPFPDD_CAPTURE_PARAM(ctypes.Structure):
    _fields_ = [
        ("size", ctypes.c_uint),
        ("image_fmt", ctypes.c_uint),
        ("image_proc", ctypes.c_uint),
        ("image_res", ctypes.c_uint),
    ]


class DPFPDD_CAPTURE_RESULT(ctypes.Structure):
    _fields_ = [
        ("size", ctypes.c_uint),
        ("success", ctypes.c_uint),
        ("quality", ctypes.c_uint),
        ("score", ctypes.c_uint),
        ("info", ctypes.c_uint),
    ]


def _read_digitalpersona_uareu_fingerprint(timeout_ms: int = 10000) -> str:
    """Capture one fingerprint image using DigitalPersona U.are.U SDK.

    Requires U.are.U runtime DLLs (dpfpdd.dll) to be installed and available in PATH.
    Returns base64-encoded raw image bytes as deterministic fingerprint input data.
    """

    if os.name != "nt":
        raise RuntimeError("DigitalPersona SDK capture is supported only on Windows hosts.")

    dpfpdd = ctypes.WinDLL("dpfpdd.dll")

    # dpfpdd API signatures used below:
    # - int dpfpdd_init(void)
    # - int dpfpdd_exit(void)
    # - int dpfpdd_query_devices(unsigned int* count, dpfpdd_dev_info* info)
    # - int dpfpdd_open(char* name, void** hReader)
    # - int dpfpdd_close(void* hReader)
    # - int dpfpdd_capture(void* hReader, dpfpdd_capture_param* p, unsigned int timeout,
    #                     unsigned char* image, unsigned int* image_size, dpfpdd_capture_result* r)
    dpfpdd.dpfpdd_init.restype = ctypes.c_int
    dpfpdd.dpfpdd_exit.restype = ctypes.c_int
    dpfpdd.dpfpdd_query_devices.argtypes = [ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(DPFPDD_DEV)]
    dpfpdd.dpfpdd_query_devices.restype = ctypes.c_int
    dpfpdd.dpfpdd_open.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
    dpfpdd.dpfpdd_open.restype = ctypes.c_int
    dpfpdd.dpfpdd_close.argtypes = [ctypes.c_void_p]
    dpfpdd.dpfpdd_close.restype = ctypes.c_int
    dpfpdd.dpfpdd_capture.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(DPFPDD_CAPTURE_PARAM),
        ctypes.c_uint,
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.POINTER(ctypes.c_uint),
        ctypes.POINTER(DPFPDD_CAPTURE_RESULT),
    ]
    dpfpdd.dpfpdd_capture.restype = ctypes.c_int

    if dpfpdd.dpfpdd_init() != 0:
        raise RuntimeError("dpfpdd_init failed. Check DigitalPersona runtime installation.")

    reader_handle = ctypes.c_void_p()
    try:
        count = ctypes.c_uint(0)
        rc = dpfpdd.dpfpdd_query_devices(ctypes.byref(count), None)
        if rc != 0 or count.value == 0:
            raise RuntimeError("No DigitalPersona readers found.")

        devices = (DPFPDD_DEV * count.value)()
        rc = dpfpdd.dpfpdd_query_devices(ctypes.byref(count), devices)
        if rc != 0:
            raise RuntimeError(f"dpfpdd_query_devices failed with code {rc}")

        rc = dpfpdd.dpfpdd_open(devices[0].name, ctypes.byref(reader_handle))
        if rc != 0:
            raise RuntimeError(f"dpfpdd_open failed with code {rc}")

        # DPFPDD_IMG_FMT_ISOIEC19794 is typically 0x001B0001 in U.are.U SDK constants.
        capture_param = DPFPDD_CAPTURE_PARAM(
            size=ctypes.sizeof(DPFPDD_CAPTURE_PARAM),
            image_fmt=0x001B0001,
            image_proc=0,
            image_res=500,
        )
        capture_result = DPFPDD_CAPTURE_RESULT(size=ctypes.sizeof(DPFPDD_CAPTURE_RESULT))

        image_size = ctypes.c_uint(1024 * 1024)
        image = (ctypes.c_ubyte * image_size.value)()

        rc = dpfpdd.dpfpdd_capture(
            reader_handle,
            ctypes.byref(capture_param),
            ctypes.c_uint(timeout_ms),
            image,
            ctypes.byref(image_size),
            ctypes.byref(capture_result),
        )
        if rc != 0 or capture_result.success == 0:
            raise RuntimeError(f"Fingerprint capture failed (rc={rc}, success={capture_result.success}).")

        raw = bytes(image[: image_size.value])
        return base64.b64encode(raw).decode("ascii")
    finally:
        if reader_handle.value:
            dpfpdd.dpfpdd_close(reader_handle)
        dpfpdd.dpfpdd_exit()


def read_fingerprint_from_sensor() -> str:
    """Read fingerprint from DigitalPersona scanner.

    For non-hardware/local testing you can set CP_FP_MOCK_DATA environment variable.
    """

    mock_data = os.getenv("CP_FP_MOCK_DATA", "").strip()
    if mock_data:
        return mock_data

    return _read_digitalpersona_uareu_fingerprint()


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
