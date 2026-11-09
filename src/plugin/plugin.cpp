#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>

#include "mail_pipeline.hpp"
#include "sqlite_store.hpp"
#include "tokenizer.hpp"
#include "data_paths.hpp"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <algorithm>
#include <cctype>
#include <unordered_map>

int show_plugin_setup(HWND);

namespace {
constexpr std::size_t kMaxMessageBytes = 5u * 1024u * 1024u;
constexpr std::uint64_t kDefaultLogLimit = 5u * 1024u * 1024u;
constexpr std::uint64_t kTestLogLimit = 20u * 1024u * 1024u;

struct PluginInfo {
    char name[80];
    char vendor[80];
    char version[80];
    char description[256];
};
struct LogSettings {
    bool enabled = true;
    bool test_mode = false;
};
std::mutex g_mutex;
std::unique_ptr<beckyas::SqliteStore> g_store;
std::unique_ptr<beckyas::MailPipeline> g_pipeline;
std::filesystem::path g_data_dir, g_audit_log, g_debug_log;
LogSettings g_log_settings;
using BeckyAllocFn = LPVOID (WINAPI*)(DWORD);
using BeckyGetSourceFn = LPSTR (WINAPI*)(LPCSTR);
using BeckySetSourceFn = void (WINAPI*)(LPCSTR, LPCSTR);
BeckyAllocFn g_becky_alloc = nullptr;
BeckyGetSourceFn g_becky_get_source = nullptr;
BeckySetSourceFn g_becky_set_source = nullptr;
// mail ID -> classification header; applied after the receive batch is saved.
std::unordered_map<std::string, std::string> g_pending_headers;
constexpr int kActionAddHeader = 8;
constexpr int kFilterPass = 1;
constexpr char kClassificationHeader[] = "x-becky-antispam";

void log_line(const std::filesystem::path& path, const char* level,
              const std::string& message, std::uint64_t limit) noexcept {
    try {
        std::error_code ec;
        if (std::filesystem::exists(path, ec) && !ec &&
            std::filesystem::file_size(path, ec) >= limit && !ec) {
            auto old = path; old += L".1";
            std::filesystem::remove(old, ec); ec.clear();
            std::filesystem::rename(path, old, ec);
        }
        SYSTEMTIME now{}; GetLocalTime(&now);
        FILE* file = nullptr;
        if (_wfopen_s(&file, path.c_str(), L"ab") != 0 || !file) return;
        std::fprintf(file, "%04u-%02u-%02u %02u:%02u:%02u [%s] ",
            now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond, level);
        // Prevent log injection; never write message source, headers or body here.
        for (char c : message) {
            if (c == '\r' || c == '\n') std::fputc(' ', file);
            else std::fputc(c, file);
        }
        std::fputs("\r\n", file);
        std::fclose(file);
    } catch (...) {}
}
void operational_log(const char* level, const std::string& message) noexcept {
    if (g_log_settings.enabled)
        log_line(g_audit_log, level, message, kDefaultLogLimit);
}
void test_log(const char* level, const std::string& message) noexcept {
    if (g_log_settings.enabled && g_log_settings.test_mode)
        log_line(g_debug_log, level, message, kTestLogLimit);
}

bool initialize_plugin() {
    // Becky! SDK: BKA_Alloc allocates callback-lifetime memory for filter parameters.
    const auto becky_module = GetModuleHandleW(nullptr);
    g_becky_alloc = becky_module
        ? reinterpret_cast<BeckyAllocFn>(GetProcAddress(becky_module, "BKA_Alloc"))
        : nullptr;
    g_becky_get_source = becky_module
        ? reinterpret_cast<BeckyGetSourceFn>(GetProcAddress(becky_module, "BKA_GetSource"))
        : nullptr;
    g_becky_set_source = becky_module
        ? reinterpret_cast<BeckySetSourceFn>(GetProcAddress(becky_module, "BKA_SetSource"))
        : nullptr;
    std::wstring path_error;
    if (!beckyas::plugin::prepare_data_directory(g_data_dir, &path_error)) {
        OutputDebugStringW((L"BeckyAntiSpam: " + path_error + L"\n").c_str());
        return false;
    }
    const std::wstring db_path = (g_data_dir / L"training.sqlite3").wstring();
    const int db_bytes = WideCharToMultiByte(CP_UTF8, 0, db_path.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (db_bytes <= 1) return false;
    std::string db_utf8(static_cast<std::size_t>(db_bytes), '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, db_path.c_str(), -1, db_utf8.data(), db_bytes, nullptr, nullptr) <= 0) return false;
    db_utf8.pop_back();
    g_audit_log = g_data_dir / L"operation.log";
    g_debug_log = g_data_dir / L"test-detail.log";

    const auto ini = g_data_dir / L"settings.ini";
    g_log_settings.enabled = GetPrivateProfileIntW(L"logging", L"enabled", 1, ini.c_str()) != 0;
    g_log_settings.test_mode = GetPrivateProfileIntW(L"test_mode", L"enabled", 0, ini.c_str()) != 0;
    operational_log("INFO", std::string("startup logging=") +
        (g_log_settings.enabled ? "on" : "off") + " test_mode=" +
        (g_log_settings.test_mode ? "on" : "off"));

    g_store = std::make_unique<beckyas::SqliteStore>(db_utf8);
    g_pipeline = std::make_unique<beckyas::MailPipeline>(*g_store);
    std::string error;
    if (!g_pipeline->initialize(&error)) {
        operational_log("ERROR", "initialization failed: " + error);
        g_pipeline.reset(); g_store.reset(); return false;
    }
    operational_log("INFO", "pipeline initialized");
    return true;
}

} // namespace


BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(instance);
    return TRUE;
}

extern "C" {
int WINAPI BKC_OnStart() {
    try {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_pipeline) initialize_plugin();
    } catch (...) { OutputDebugStringA("BeckyAntiSpam: startup exception.\n"); }
    return 0;
}
int WINAPI BKC_OnExit() {
    try {
        std::lock_guard<std::mutex> lock(g_mutex);
        operational_log("INFO", "shutdown");
        g_pipeline.reset(); g_store.reset();
    } catch (...) {}
    return 0;
}
int WINAPI BKC_OnMenuInit(HWND, HMENU, int) {
    return 0;
}
int WINAPI BKC_OnPlugInSetup(HWND hwnd) {
    try {
        return show_plugin_setup(hwnd);
    } catch (...) {
        OutputDebugStringA("BeckyAntiSpam: settings dialog exception.\\n");
        return 0;
    }
}
int WINAPI BKC_OnPlugInInfo(PluginInfo* info) {
    if (!info) return 0;
    std::strncpy(info->name, "Becky AntiSpam", sizeof(info->name) - 1);
    std::strncpy(info->vendor, "noname2007jp", sizeof(info->vendor) - 1);
    std::strncpy(info->version, "0.1.0", sizeof(info->version) - 1);
    std::strncpy(info->description, "Local spam classification (audit mode)", sizeof(info->description) - 1);
    return 0;
}
int WINAPI BKC_OnBeforeFilter2(LPCSTR message, LPCSTR, int* action, char** parameter) {
    if (action) *action = -1; // ACTION_NOTHING
    if (parameter) *parameter = nullptr;
    if (!message || !action || !parameter) return 0;

    try {
        std::string source(message);
        // OnBeforeFilter2 receives the same SMTP-style terminator as OnRetrieve.
        constexpr char kSmtpTerminator[] = "\r\n.\r\n";
        if (source.size() >= sizeof(kSmtpTerminator) - 1 &&
            source.compare(source.size() - (sizeof(kSmtpTerminator) - 1),
                sizeof(kSmtpTerminator) - 1, kSmtpTerminator) == 0) {
            source.resize(source.size() - (sizeof(kSmtpTerminator) - 1));
        }
        if (source.empty() || source.size() > kMaxMessageBytes) return 0;

        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_pipeline && !initialize_plugin()) {
            operational_log("ERROR", "filter annotation skipped: pipeline unavailable");
            return 0;
        }
        if (!g_becky_alloc) {
            operational_log("ERROR", "filter annotation unavailable: BKA_Alloc not found");
            return 0;
        }

        beckyas::ParsedMail parsed;
        beckyas::Result result;
        std::string error;
        if (!g_pipeline->analyze(source, parsed, result, &error)) {
            operational_log("ERROR", "filter analysis failed: " + error);
            return 0;
        }

        const bool has_classification_header = std::any_of(
            parsed.headers.begin(), parsed.headers.end(),
            [](const beckyas::HeaderField& field) {
                std::string name = field.name;
                std::transform(name.begin(), name.end(), name.begin(),
                    [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                return name == kClassificationHeader;
            });
        if (has_classification_header) {
            operational_log("INFO", "filter annotation skipped: classification header already exists");
            return kFilterPass;
        }

        const char* label = result.verdict == beckyas::Verdict::Spam ? "Spam" :
            result.verdict == beckyas::Verdict::Review ? "Review" : "Ham";
        const std::string header = std::string("X-Becky-AntiSpam: ") + label;
        auto* callback_buffer = static_cast<char*>(g_becky_alloc(
            static_cast<DWORD>(header.size() + 1)));
        if (!callback_buffer) {
            operational_log("ERROR", "filter annotation failed: BKA_Alloc returned null");
            return 0;
        }
        std::memcpy(callback_buffer, header.c_str(), header.size() + 1);
        *action = kActionAddHeader;
        *parameter = callback_buffer;

        const char* verdict = result.verdict == beckyas::Verdict::Spam ? "spam" :
            result.verdict == beckyas::Verdict::Review ? "review" : "ham";
        operational_log("INFO", std::string("filter header requested verdict=") + verdict);
        return kFilterPass;
    } catch (...) {
        operational_log("ERROR", "unexpected exception in filter annotation callback");
        return 0;
    }
}

int WINAPI BKC_OnRetrieve(LPCSTR message, LPCSTR mail_id) {
    // Keep only the classification marker and mail ID. The full source is not
    // retained; the saved source is updated after the receive batch completes.
    if (!message || !mail_id || !*mail_id) return 0;
    const char* marker = "X-Becky-AntiSpam: ";
    const char* found = std::strstr(message, marker);
    if (!found) {
        operational_log("WARN", "retrieve callback classification header not present");
        return 0;
    }
    const char* value = found + std::strlen(marker);
    const char* end = std::strpbrk(value, "\r\n");
    if (!end || end == value) return 0;
    const std::string header = std::string(marker) + std::string(value, end);
    try {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_pending_headers[mail_id] = header;
    } catch (...) {
        operational_log("ERROR", "failed to queue classification header for post-retrieve update");
        return 0;
    }
    operational_log("INFO", "retrieve callback classification header queued");
    return 0;
}

int WINAPI BKC_OnFinishRetrieve(int message_count) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_pending_headers.empty()) return 0;
    if (!g_becky_get_source || !g_becky_set_source) {
        operational_log("ERROR", "post-retrieve source update unavailable: Becky source API not found");
        g_pending_headers.clear();
        return 0;
    }

    std::size_t updated = 0;
    std::size_t failed = 0;
    for (const auto& item : g_pending_headers) {
        const auto* mail_id = item.first.c_str();
        const auto* current_ptr = g_becky_get_source(mail_id);
        if (!current_ptr) {
            ++failed;
            continue;
        }
        std::string source(current_ptr);
        if (source.find(item.second) != std::string::npos) {
            ++updated; // Already persisted; no rewrite required.
            continue;
        }

        // Insert the marker before the existing RFC 5322 header block.
        const auto separator = source.find("\r\n\r\n");
        if (separator == std::string::npos) {
            ++failed;
            continue;
        }
        source.insert(separator + 2, item.second + "\r\n");
        g_becky_set_source(mail_id, source.c_str());

        const auto* verify_ptr = g_becky_get_source(mail_id);
        if (verify_ptr && std::string(verify_ptr).find(item.second) != std::string::npos)
            ++updated;
        else
            ++failed;
    }
    operational_log(failed == 0 ? "INFO" : "WARN",
        std::string("post-retrieve header update completed updated=") +
        std::to_string(updated) + " failed=" + std::to_string(failed) +
        " batch_messages=" + std::to_string(message_count));
    g_pending_headers.clear();
    return 0;
}
}
