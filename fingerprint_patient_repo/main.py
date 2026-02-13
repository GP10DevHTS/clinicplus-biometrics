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


# ---------------------------------------------------------------------------
# Backend: Windows Biometric Framework (WBF) - HID/DigitalPersona compatible
# Uses winbio.dll; works with readers that have a WBF driver (e.g. many DP readers).
# ---------------------------------------------------------------------------

# WBF constants (winbio.h)
WINBIO_TYPE_FINGERPRINT = 0x00000008
WINBIO_POOL_SYSTEM = 0x00000001
WINBIO_FLAG_RAW = 0x00000008
WINBIO_DB_DEFAULT = 0x00000000
WINBIO_NO_PURPOSE_AVAILABLE = 0
WINBIO_DATA_FLAG_RAW = 0x00000001
S_OK = 0


def _read_fingerprint_wbf() -> str:
    """Capture fingerprint using Windows Biometric Framework (winbio.dll).

    Compatible with HID DigitalPersona and other readers that support WBF.
    Requires WINBIO_FLAG_RAW capability (admin or appropriate policy).
    """
    if os.name != "nt":
        raise RuntimeError("Windows Biometric Framework is supported only on Windows.")

    winbio = ctypes.WinDLL("winbio.dll")
    # WinBioOpenSession( Factor, PoolType, Flags, UnitArray, UnitCount, DatabaseId, &SessionHandle )
    winbio.WinBioOpenSession.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    winbio.WinBioOpenSession.restype = ctypes.HRESULT  # c_long
    # WinBioCaptureSample( SessionHandle, Purpose, Flags, UnitId, Sample, SampleSize, RejectDetail )
    winbio.WinBioCaptureSample.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    winbio.WinBioCaptureSample.restype = ctypes.HRESULT
    winbio.WinBioFree.argtypes = [ctypes.c_void_p]
    winbio.WinBioFree.restype = None
    winbio.WinBioCloseSession.argtypes = [ctypes.c_void_p]
    winbio.WinBioCloseSession.restype = ctypes.HRESULT

    session = ctypes.c_void_p()
    hr = winbio.WinBioOpenSession(
        WINBIO_TYPE_FINGERPRINT,
        WINBIO_POOL_SYSTEM,
        WINBIO_FLAG_RAW,
        None,
        0,
        WINBIO_DB_DEFAULT,
        ctypes.byref(session),
    )
    if hr != S_OK:
        raise RuntimeError(
            f"WinBioOpenSession failed (HRESULT=0x{hr & 0xFFFFFFFF:08X}). "
            "Ensure a WBF-compatible fingerprint reader is installed and you have raw capture access."
        )

    try:
        unit_id = ctypes.c_uint32(0)
        sample_ptr = ctypes.c_void_p()
        sample_size = ctypes.c_size_t(0)
        reject_detail = ctypes.c_uint32(0)
        hr = winbio.WinBioCaptureSample(
            session,
            WINBIO_NO_PURPOSE_AVAILABLE,
            WINBIO_DATA_FLAG_RAW,
            ctypes.byref(unit_id),
            ctypes.byref(sample_ptr),
            ctypes.byref(sample_size),
            ctypes.byref(reject_detail),
        )
        if hr != S_OK:
            raise RuntimeError(
                f"WinBioCaptureSample failed (HRESULT=0x{hr & 0xFFFFFFFF:08X}, RejectDetail={reject_detail.value})."
            )
        if not sample_ptr.value or sample_size.value == 0:
            raise RuntimeError("WinBioCaptureSample returned no data.")
        raw = ctypes.string_at(sample_ptr.value, sample_size.value)
        return base64.b64encode(raw).decode("ascii")
    finally:
        if sample_ptr.value:
            winbio.WinBioFree(sample_ptr.value)
        winbio.WinBioCloseSession(session)


# ---------------------------------------------------------------------------
# Backend: DigitalPersona U.are.U SDK (dpfpdd.dll) - HID/DP device API
# ---------------------------------------------------------------------------

# SDK constants (from dpfpdd.h)
MAX_STR_LENGTH = 128
MAX_DEVICE_NAME_LENGTH = 1024


class DPFPDD_VER_INFO(ctypes.Structure):
    _fields_ = [
        ("major", ctypes.c_int),
        ("minor", ctypes.c_int),
        ("maintenance", ctypes.c_int),
    ]


class DPFPDD_HW_DESCR(ctypes.Structure):
    _fields_ = [
        ("vendor_name", ctypes.c_char * MAX_STR_LENGTH),
        ("product_name", ctypes.c_char * MAX_STR_LENGTH),
        ("serial_num", ctypes.c_char * MAX_STR_LENGTH),
    ]


class DPFPDD_HW_ID(ctypes.Structure):
    _fields_ = [
        ("vendor_id", ctypes.c_ushort),
        ("product_id", ctypes.c_ushort),
    ]


class DPFPDD_HW_VERSION(ctypes.Structure):
    _fields_ = [
        ("hw_ver", DPFPDD_VER_INFO),
        ("fw_ver", DPFPDD_VER_INFO),
        ("bcd_rev", ctypes.c_ushort),
    ]


class DPFPDD_DEV_INFO(ctypes.Structure):
    """Reader info from dpfpdd_query_devices (per SDK dpfpdd_dev_info)."""
    _fields_ = [
        ("size", ctypes.c_uint),
        ("name", ctypes.c_char * MAX_DEVICE_NAME_LENGTH),
        ("descr", DPFPDD_HW_DESCR),
        ("id", DPFPDD_HW_ID),
        ("ver", DPFPDD_HW_VERSION),
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


class DPFPDD_IMAGE_INFO(ctypes.Structure):
    _fields_ = [
        ("size", ctypes.c_uint),
        ("width", ctypes.c_uint),
        ("height", ctypes.c_uint),
        ("res", ctypes.c_uint),
        ("bpp", ctypes.c_uint),
    ]


class DPFPDD_CAPTURE_RESULT(ctypes.Structure):
    _fields_ = [
        ("size", ctypes.c_uint),
        ("success", ctypes.c_int),
        ("quality", ctypes.c_uint),
        ("score", ctypes.c_uint),
        ("info", DPFPDD_IMAGE_INFO),
    ]


def _get_dpfpdd_dll():
    """Load dpfpdd.dll from DigitalPersona SDK path (SDK uses __stdcall). winmode=0 so dependencies resolve."""
    sdk_paths = [
        os.environ.get("DPFPDD_PATH"),
        r"C:\Users\gp10devhts\Downloads\dpfpdd\dpfpdd.dll",
        r"C:\Program Files\DigitalPersona\Bin\dpfpdd.dll",
        r"C:\Program Files\DigitalPersona\dpfpdd.dll",
        "dpfpdd.dll",
    ]
    for path in sdk_paths:
        if not path:
            continue
        if os.path.isfile(path):
            # WinDLL = __stdcall per SDK header; winmode=0 (Py3.8+) helps resolve DLL dependencies
            try:
                return ctypes.WinDLL(path, winmode=0)
            except (OSError, TypeError, AttributeError):
                pass
            try:
                return ctypes.WinDLL(path)
            except OSError:
                pass
    raise OSError("dpfpdd.dll not found. Set DPFPDD_PATH or install DigitalPersona U.are.U SDK.")


def _read_digitalpersona_uareu_fingerprint(timeout_ms: int = 10000) -> str:
    """Capture one fingerprint image using DigitalPersona U.are.U SDK.

    Requires U.are.U runtime DLLs (dpfpdd.dll) from SDK install (e.g. C:\\Program Files\\DigitalPersona\\).
    Returns base64-encoded raw image bytes as deterministic fingerprint input data.
    """

    if os.name != "nt":
        raise RuntimeError("DigitalPersona SDK capture is supported only on Windows hosts.")

    dpfpdd = _get_dpfpdd_dll()

    # dpfpdd API (SDK uses __stdcall). See dpfpdd.h:
    # dpfpdd_query_devices(unsigned int* dev_cnt, DPFPDD_DEV_INFO* dev_infos)
    # dpfpdd_capture(dev, capture_parm, timeout_cnt, capture_result, image_size, image_data)
    dpfpdd.dpfpdd_init.restype = ctypes.c_int
    dpfpdd.dpfpdd_exit.restype = ctypes.c_int
    dpfpdd.dpfpdd_query_devices.argtypes = [ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(DPFPDD_DEV_INFO)]
    dpfpdd.dpfpdd_query_devices.restype = ctypes.c_int
    dpfpdd.dpfpdd_open.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
    dpfpdd.dpfpdd_open.restype = ctypes.c_int
    dpfpdd.dpfpdd_close.argtypes = [ctypes.c_void_p]
    dpfpdd.dpfpdd_close.restype = ctypes.c_int
    dpfpdd.dpfpdd_capture.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(DPFPDD_CAPTURE_PARAM),
        ctypes.c_uint,
        ctypes.POINTER(DPFPDD_CAPTURE_RESULT),
        ctypes.POINTER(ctypes.c_uint),
        ctypes.POINTER(ctypes.c_ubyte),
    ]
    dpfpdd.dpfpdd_capture.restype = ctypes.c_int

    if dpfpdd.dpfpdd_init() != 0:
        raise RuntimeError("dpfpdd_init failed. Check DigitalPersona runtime installation.")

    reader_handle = ctypes.c_void_p()
    try:
        max_readers = 16
        count = ctypes.c_uint(max_readers)
        dev_infos = (DPFPDD_DEV_INFO * max_readers)()
        for i in range(max_readers):
            dev_infos[i].size = ctypes.sizeof(DPFPDD_DEV_INFO)
        rc = dpfpdd.dpfpdd_query_devices(ctypes.byref(count), dev_infos)
        if rc != 0:
            raise RuntimeError(
                f"dpfpdd_query_devices failed (rc={rc}, 0x{rc & 0xFFFFFFFF:X}). "
                "Ensure the DigitalPersona U.are.U SDK/runtime is installed and matches your reader model."
            )
        if count.value == 0:
            raise RuntimeError(
                "No DigitalPersona readers found (count=0). "
                "Scanner may be using a generic USB driver; install the official DigitalPersona U.are.U "
                "SDK/drivers and ensure the device appears in Device Manager under DigitalPersona or Biometric devices."
            )
        num_devices = min(count.value, max_readers)

        rc = dpfpdd.dpfpdd_open(dev_infos[0].name, ctypes.byref(reader_handle))
        if rc != 0:
            raise RuntimeError(f"dpfpdd_open failed with code {rc}")

        # DPFPDD_IMG_FMT_ISOIEC19794 = 0x01010007 per dpfpdd.h
        capture_param = DPFPDD_CAPTURE_PARAM(
            size=ctypes.sizeof(DPFPDD_CAPTURE_PARAM),
            image_fmt=0x01010007,
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
            ctypes.byref(capture_result),
            ctypes.byref(image_size),
            image,
        )
        if rc != 0 or capture_result.success != 1:
            raise RuntimeError(f"Fingerprint capture failed (rc={rc}, success={capture_result.success}).")

        raw = bytes(image[: image_size.value])
        return base64.b64encode(raw).decode("ascii")
    finally:
        if reader_handle.value:
            dpfpdd.dpfpdd_close(reader_handle)
        dpfpdd.dpfpdd_exit()


def diagnose_digitalpersona_sdk() -> None:
    """Print diagnostics for WBF and DigitalPersona (dpfpdd) backends."""
    if os.name != "nt":
        print("Diagnostics are for Windows only.")
        return
    backend = _get_fingerprint_backend()
    print(f"Backend selection: {backend} (set CP_FP_BACKEND=wbf|dpfpdd|auto or use --backend)\n")

    # --- WBF (Windows Biometric Framework) ---
    print("--- Windows Biometric Framework (WBF / HID-compatible) ---")
    try:
        winbio = ctypes.WinDLL("winbio.dll")
        winbio.WinBioOpenSession.argtypes = [
            ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,
            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        winbio.WinBioOpenSession.restype = ctypes.HRESULT
        session = ctypes.c_void_p()
        hr = winbio.WinBioOpenSession(
            WINBIO_TYPE_FINGERPRINT, WINBIO_POOL_SYSTEM, WINBIO_FLAG_RAW,
            None, 0, WINBIO_DB_DEFAULT, ctypes.byref(session),
        )
        if hr == S_OK:
            print("  WinBioOpenSession: OK (WBF backend available)")
            winbio.WinBioCloseSession.argtypes = [ctypes.c_void_p]
            winbio.WinBioCloseSession.restype = ctypes.HRESULT
            winbio.WinBioCloseSession(session)
        else:
            print(f"  WinBioOpenSession: failed (HRESULT=0x{hr & 0xFFFFFFFF:08X})")
    except Exception as e:
        print(f"  WBF: {e}")

    # --- DigitalPersona dpfpdd ---
    print("\n--- DigitalPersona U.are.U SDK (dpfpdd.dll) ---")
    try:
        dpfpdd = _get_dpfpdd_dll()
    except OSError as e:
        print(f"  Failed to load dpfpdd.dll: {e}")
        return
    dpfpdd.dpfpdd_query_devices.argtypes = [ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(DPFPDD_DEV_INFO)]
    dpfpdd.dpfpdd_query_devices.restype = ctypes.c_int
    init_rc = dpfpdd.dpfpdd_init()
    print(f"  dpfpdd_init() = {init_rc}")
    if init_rc != 0:
        dpfpdd.dpfpdd_exit()
        return
    count = ctypes.c_uint(16)
    dev_infos = (DPFPDD_DEV_INFO * 16)()
    for i in range(16):
        dev_infos[i].size = ctypes.sizeof(DPFPDD_DEV_INFO)
    rc = dpfpdd.dpfpdd_query_devices(ctypes.byref(count), dev_infos)
    dpfpdd.dpfpdd_exit()
    print(f"  dpfpdd_query_devices() = {rc}, count = {count.value}")
    for i in range(min(count.value, 16)):
        name = dev_infos[i].name
        if isinstance(name, bytes):
            name = name.decode("utf-8", errors="replace").strip("\x00")
        print(f"    device[{i}] name = {name!r}")
    if count.value == 0:
        print("  Tip: Install DigitalPersona U.are.U SDK or use --backend wbf if the reader has a WBF driver.")
    return


def _get_fingerprint_backend() -> str:
    """Return 'wbf' or 'dpfpdd'. Env CP_FP_BACKEND can be 'wbf', 'dpfpdd', or 'auto' (default)."""
    backend = (os.environ.get("CP_FP_BACKEND") or "auto").strip().lower()
    if backend in ("wbf", "dpfpdd"):
        return backend
    return "auto"


def read_fingerprint_from_sensor() -> str:
    """Read fingerprint using HID/Windows API: WBF (Windows Biometric Framework) or DigitalPersona dpfpdd."""
    backend = _get_fingerprint_backend()
    if backend == "wbf" or backend == "auto":
        try:
            return _read_fingerprint_wbf()
        except (RuntimeError, OSError) as e:
            if backend == "wbf":
                raise
            # auto: fall back to dpfpdd
            pass
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
    parser.add_argument(
        "--diagnose",
        action="store_true",
        help="Run SDK/reader diagnostics and exit (no capture).",
    )
    parser.add_argument(
        "--backend",
        choices=("auto", "wbf", "dpfpdd"),
        default=None,
        help="Fingerprint API: wbf (Windows Biometric Framework), dpfpdd (DigitalPersona SDK), or auto (default: try wbf then dpfpdd).",
    )
    args = parser.parse_args()

    if args.backend is not None:
        os.environ["CP_FP_BACKEND"] = args.backend

    if args.diagnose:
        diagnose_digitalpersona_sdk()
        return

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
