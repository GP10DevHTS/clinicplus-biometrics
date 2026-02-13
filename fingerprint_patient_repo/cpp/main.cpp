#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <winbio.h>
#pragma comment(lib, "winbio.lib")
#endif

namespace fs = std::filesystem;

struct MatchResult {
    bool is_existing;
    std::string patient_code;
};

class Sha256 {
public:
    static std::string hash(const std::string& input) {
        Sha256 sha;
        sha.update(reinterpret_cast<const uint8_t*>(input.data()), input.size());
        sha.finalize();
        return sha.hexdigest();
    }

private:
    std::array<uint32_t, 8> state_ = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    std::array<uint8_t, 64> buffer_{};
    uint64_t bit_len_ = 0;
    size_t buffer_len_ = 0;

    static constexpr std::array<uint32_t, 64> K = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };

    static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

    void transform(const uint8_t block[64]) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3];
        }
        for (int i = 16; i < 64; ++i) {
            const uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
        uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];

        for (int i = 0; i < 64; ++i) {
            const uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const uint32_t ch = (e & f) ^ ((~e) & g);
            const uint32_t temp1 = h + S1 + ch + K[i] + w[i];
            const uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const uint32_t temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
        state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
    }

    void update(const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            buffer_[buffer_len_++] = data[i];
            if (buffer_len_ == 64) {
                transform(buffer_.data());
                bit_len_ += 512;
                buffer_len_ = 0;
            }
        }
    }

    void finalize() {
        bit_len_ += buffer_len_ * 8;

        buffer_[buffer_len_++] = 0x80;
        if (buffer_len_ > 56) {
            while (buffer_len_ < 64) buffer_[buffer_len_++] = 0;
            transform(buffer_.data());
            buffer_len_ = 0;
        }
        while (buffer_len_ < 56) buffer_[buffer_len_++] = 0;

        for (int i = 7; i >= 0; --i) {
            buffer_[buffer_len_++] = static_cast<uint8_t>((bit_len_ >> (i * 8)) & 0xFF);
        }
        transform(buffer_.data());
    }

    std::string hexdigest() const {
        std::ostringstream os;
        for (uint32_t s : state_) {
            os << std::hex << std::setw(8) << std::setfill('0') << s;
        }
        return os.str();
    }
};

class FingerprintRegistry {
public:
    explicit FingerprintRegistry(fs::path db_path) : db_path_(std::move(db_path)) { load(); }

    MatchResult identify_or_register(const std::string& fingerprint_data) {
        const auto fingerprint_hash = Sha256::hash(fingerprint_data);
        auto it = records_.find(fingerprint_hash);
        if (it != records_.end()) {
            return {true, it->second};
        }

        const auto patient_code = next_patient_code();
        records_[fingerprint_hash] = patient_code;
        save();
        return {false, patient_code};
    }

private:
    fs::path db_path_;
    std::map<std::string, std::string> records_;

    void load() {
        records_.clear();
        if (!fs::exists(db_path_)) return;

        std::ifstream in(db_path_);
        std::string line;
        while (std::getline(in, line)) {
            auto tab = line.find('\t');
            if (tab == std::string::npos) continue;
            records_[line.substr(0, tab)] = line.substr(tab + 1);
        }
    }

    void save() const {
        fs::create_directories(db_path_.parent_path());
        std::ofstream out(db_path_, std::ios::trunc);
        for (const auto& [hash, code] : records_) {
            out << hash << '\t' << code << '\n';
        }
    }

    std::string next_patient_code() const {
        std::ostringstream os;
        os << "PAT" << std::setw(5) << std::setfill('0') << (records_.size() + 1);
        return os.str();
    }
};

std::string build_redirect_url(const std::string& base_url, const MatchResult& result) {
    std::string base = base_url;
    while (!base.empty() && base.back() == '/') base.pop_back();

    if (result.is_existing) return base + "/existing-patient?patient_code=" + result.patient_code;
    return base + "/new-patient";
}

#ifdef _WIN32
std::string capture_fingerprint_wbf() {
    WINBIO_SESSION_HANDLE session = nullptr;
    HRESULT hr = WinBioOpenSession(
        WINBIO_TYPE_FINGERPRINT,
        WINBIO_POOL_SYSTEM,
        WINBIO_FLAG_RAW,
        nullptr,
        0,
        WINBIO_DB_DEFAULT,
        &session
    );
    if (FAILED(hr)) {
        throw std::runtime_error("WinBioOpenSession failed");
    }

    WINBIO_UNIT_ID unit_id = 0;
    PWINBIO_BIR sample = nullptr;
    SIZE_T sample_size = 0;
    WINBIO_REJECT_DETAIL reject_detail = 0;

    hr = WinBioCaptureSample(
        session,
        WINBIO_NO_PURPOSE_AVAILABLE,
        WINBIO_DATA_FLAG_RAW,
        &unit_id,
        &sample,
        &sample_size,
        &reject_detail
    );
    WinBioCloseSession(session);

    if (FAILED(hr) || sample == nullptr || sample_size == 0) {
        throw std::runtime_error("WinBioCaptureSample failed");
    }

    std::string raw(reinterpret_cast<const char*>(sample), sample_size);
    WinBioFree(sample);
    return raw;
}

using dpfpdd_handle = void*;

struct DpfpddCaptureParam {
    unsigned int size;
    unsigned int image_fmt;
    unsigned int image_proc;
    unsigned int image_res;
};
struct DpfpddImageInfo {
    unsigned int size;
    unsigned int width;
    unsigned int height;
    unsigned int res;
    unsigned int bpp;
};
struct DpfpddCaptureResult {
    unsigned int size;
    int success;
    unsigned int quality;
    unsigned int score;
    DpfpddImageInfo info;
};

std::string capture_fingerprint_dpfpdd() {
    HMODULE dll = LoadLibraryA("dpfpdd.dll");
    if (!dll) throw std::runtime_error("Could not load dpfpdd.dll");

    auto dpfpdd_init = reinterpret_cast<int(__stdcall*)()>(GetProcAddress(dll, "dpfpdd_init"));
    auto dpfpdd_exit = reinterpret_cast<int(__stdcall*)()>(GetProcAddress(dll, "dpfpdd_exit"));
    auto dpfpdd_open = reinterpret_cast<int(__stdcall*)(const char*, dpfpdd_handle*)>(GetProcAddress(dll, "dpfpdd_open"));
    auto dpfpdd_close = reinterpret_cast<int(__stdcall*)(dpfpdd_handle)>(GetProcAddress(dll, "dpfpdd_close"));
    auto dpfpdd_capture = reinterpret_cast<int(__stdcall*)(dpfpdd_handle, DpfpddCaptureParam*, unsigned int, DpfpddCaptureResult*, unsigned int*, unsigned char*)>(
        GetProcAddress(dll, "dpfpdd_capture"));

    if (!dpfpdd_init || !dpfpdd_exit || !dpfpdd_open || !dpfpdd_close || !dpfpdd_capture) {
        FreeLibrary(dll);
        throw std::runtime_error("Missing dpfpdd exports");
    }

    if (dpfpdd_init() != 0) {
        FreeLibrary(dll);
        throw std::runtime_error("dpfpdd_init failed");
    }

    dpfpdd_handle reader = nullptr;
    int rc = dpfpdd_open("", &reader);
    if (rc != 0) {
        dpfpdd_exit();
        FreeLibrary(dll);
        throw std::runtime_error("dpfpdd_open failed");
    }

    DpfpddCaptureParam capture_param{sizeof(DpfpddCaptureParam), 0x01010007, 0, 500};
    DpfpddCaptureResult result{sizeof(DpfpddCaptureResult), 0, 0, 0, {sizeof(DpfpddImageInfo), 0, 0, 0, 0}};
    std::vector<unsigned char> image(1024 * 1024);
    unsigned int image_size = static_cast<unsigned int>(image.size());

    rc = dpfpdd_capture(reader, &capture_param, 10000, &result, &image_size, image.data());
    dpfpdd_close(reader);
    dpfpdd_exit();
    FreeLibrary(dll);

    if (rc != 0 || result.success != 1) {
        throw std::runtime_error("dpfpdd_capture failed");
    }

    return std::string(reinterpret_cast<char*>(image.data()), image_size);
}
#endif

std::string read_fingerprint_from_sensor(const std::string& backend) {
    const char* mock = std::getenv("CP_FP_MOCK_DATA");
    if (mock && std::string(mock).size() > 0) return std::string(mock);

#ifdef _WIN32
    if (backend == "wbf") return capture_fingerprint_wbf();
    if (backend == "dpfpdd") return capture_fingerprint_dpfpdd();

    try {
        return capture_fingerprint_wbf();
    } catch (...) {
        return capture_fingerprint_dpfpdd();
    }
#else
    (void)backend;
    throw std::runtime_error("Fingerprint capture is only implemented for Windows in the C++ version.");
#endif
}

void open_url(const std::string& url) {
#ifdef _WIN32
    ShellExecuteA(nullptr, "open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
#else
    std::cout << "Open URL manually: " << url << '\n';
#endif
}

int main(int argc, char** argv) {
    std::string base_url = "http://localhost:3000";
    std::string db_path = "./data/fingerprints_cpp.tsv";
    std::string backend = "auto";

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--base-url" && i + 1 < argc) base_url = argv[++i];
        else if (arg == "--db" && i + 1 < argc) db_path = argv[++i];
        else if (arg == "--backend" && i + 1 < argc) backend = argv[++i];
        else if (arg == "--diagnose") {
#ifdef _WIN32
            std::cout << "Windows mode: WBF + dpfpdd backends available if runtime/driver installed.\n";
#else
            std::cout << "Non-Windows host: capture backends unavailable.\n";
#endif
            return 0;
        }
    }

    try {
        const auto fingerprint_data = read_fingerprint_from_sensor(backend);
        FingerprintRegistry registry(db_path);
        auto result = registry.identify_or_register(fingerprint_data);
        auto url = build_redirect_url(base_url, result);

        std::cout << "Matched existing patient: " << (result.is_existing ? "true" : "false") << "\n";
        std::cout << "Patient code: " << result.patient_code << "\n";
        std::cout << "Opening: " << url << "\n";
        open_url(url);
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }

    return 0;
}
