#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>

#include "mail_pipeline.hpp"
#include "sqlite_store.hpp"

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>

namespace {

constexpr std::size_t kMaxMessageBytes = 5u * 1024u * 1024u;
constexpr std::uint64_t kMaxAuditLogBytes = 1024u * 1024u;

struct PluginInfo {
    char name[80];
    char vendor[80];
    char version[80];
    char description[256];
};

std::mutex g_mutex;
std::unique_ptr<beckyas::SqliteStore> g_store;
std::unique_ptr<beckyas::MailPipeline> g_pipeline;
std::filesystem::path g_data_dir;
std::filesystem::path g_audit_log;

bool initialize_plugin() {
    wchar_t appdata[MAX_PATH] = {};
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_APPDATA | CSIDL_FLAG_CREATE,
                                nullptr, SHGFP_TYPE_CURRENT, appdata))) {
        OutputDebugStringA("BeckyAntiSpam: cannot resolve APPDATA path.\n");
        return false;
    }

    const int utf8_size = WideCharToMultiByte(CP_UTF8, 0, appdata, -1, nullptr, 0, nullptr, nullptr);
    if (utf8_size <= 1) return false;
    std::string appdata_utf8(static_cast<std::size_t>(utf8_size - 1), '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, appdata, -1, appdata_utf8.data(),
                            utf8_size, nullptr, nullptr) <= 0) return false;

    const std::string data_dir_utf8 = appdata_utf8 + "\\BeckyAntiSpam";
    g_data_dir = std::filesystem::u8path(data_dir_utf8);
    std::filesystem::create_directories(g_data_dir);
    g_audit_log = g_data_dir / L"audit.log";

    const auto db_path = data_dir_utf8 + "\\training.sqlite3";
    g_store = std::make_unique<beckyas::SqliteStore>(db_path);
    g_pipeline = std::make_unique<beckyas::MailPipeline>(*g_store);
    std::string error;
    if (!g_pipeline->initialize(&error)) {
        OutputDebugStringA(("BeckyAntiSpam: initialization failed: " + error + "\n").c_str());
        g_pipeline.reset();
        g_store.reset();
        return false;
    }
    return true;
}

void write_audit(const beckyas::Result& result) {
    try {
        std::error_code ec;
        if (std::filesystem::exists(g_audit_log, ec) && !ec &&
            std::filesystem::file_size(g_audit_log, ec) > kMaxAuditLogBytes && !ec) {
            auto previous = g_audit_log;
            previous += L".1";
            std::filesystem::remove(previous, ec);
            ec.clear();
            std::filesystem::rename(g_audit_log, previous, ec);
        }

        SYSTEMTIME now{};
        GetLocalTime(&now);
        const char* verdict = "ham";
        if (result.verdict == beckyas::Verdict::Review) verdict = "review";
        else if (result.verdict == beckyas::Verdict::Spam) verdict = "spam";

        char line[256] = {};
        std::snprintf(line, sizeof(line), "%04u-%02u-%02u %02u:%02u:%02u verdict=%s score=%d bayes=%.4f\r\n",
            now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond,
            verdict, result.score, result.bayes_probability);
        FILE* file = nullptr;
        if (_wfopen_s(&file, g_audit_log.c_str(), L"ab") == 0 && file) {
            std::fwrite(line, 1, std::strlen(line), file);
            std::fclose(file);
        }
    } catch (...) {
        // Audit logging must never interfere with mail reception.
    }
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
    } catch (...) {
        OutputDebugStringA("BeckyAntiSpam: startup exception.\n");
    }
    return 0;
}

int WINAPI BKC_OnExit() {
    try {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_pipeline.reset();
        g_store.reset();
    } catch (...) {
    }
    return 0;
}

int WINAPI BKC_OnMenuInit(HWND, HMENU, int) {
    return 0;
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
    if (action) *action = -1;       // ACTION_NOTHING
    if (parameter) *parameter = nullptr;
    if (!message) return 0;         // BKC_FILTER_DEFAULT

    try {
        const auto length = strnlen_s(message, kMaxMessageBytes + 1);
        if (length == 0 || length > kMaxMessageBytes) return 0;

        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_pipeline && !initialize_plugin()) return 0;

        beckyas::ParsedMail parsed;
        beckyas::Result result;
        std::string error;
        if (g_pipeline->analyze(std::string(message, length), parsed, result, &error))
            write_audit(result);
        else
            OutputDebugStringA(("BeckyAntiSpam: message analysis skipped: " + error + "\n").c_str());
    } catch (...) {
        OutputDebugStringA("BeckyAntiSpam: filter callback exception.\n");
    }

    // Audit-only: leave Becky!'s standard filtering untouched.
    return 0; // BKC_FILTER_DEFAULT
}

} // extern "C"
