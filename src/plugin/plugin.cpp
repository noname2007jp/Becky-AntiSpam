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

namespace {
std::wstring utf8_to_wide(const std::string& value) {
    if (value.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0);
    if (n <= 0) return L"詳細エラーはログを確認してください。";
    std::wstring out(static_cast<std::size_t>(n), L'\\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), out.data(), n) <= 0)
        return L"詳細エラーはログを確認してください。";
    return out;
}
bool wide_path_to_utf8(const std::filesystem::path& path, std::string& out) {
    const auto value = path.wstring();
    const int n = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return false;
    out.resize(static_cast<std::size_t>(n));
    if (WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, out.data(), n, nullptr, nullptr) <= 0) {
        out.clear();
        return false;
    }
    out.pop_back();
    return true;
}
}

bool export_plugin_data(const wchar_t* folder, std::wstring& error) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_store || !g_store->is_open()) { error = L"学習DBが初期化されていません。"; return false; }
    if (!folder || !*folder) { error = L"フォルダーが指定されていません。"; return false; }
    const std::filesystem::path dir(folder);
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec) { error = L"保存先フォルダーを作成できません。"; return false; }
    std::string db;
    if (!wide_path_to_utf8(dir / L"training.sqlite3", db)) { error = L"保存先パスを変換できません。"; return false; }
    std::string db_error;
    if (!g_store->backup_to(db, &db_error)) {
        error = L"学習DBのエクスポートに失敗しました: " + utf8_to_wide(db_error);
        return false;
    }
    const auto settings_path = g_data_dir / L"settings.ini";
    if (!std::filesystem::exists(settings_path)) {
        WritePrivateProfileStringW(L"logging", L"enabled", L"1", settings_path.c_str());
        WritePrivateProfileStringW(L"test_mode", L"enabled", L"0", settings_path.c_str());
    }
    if (!CopyFileW(settings_path.c_str(), (dir / L"settings.ini").c_str(), FALSE)) {
        error = L"設定ファイルをコピーできませんでした。";
        return false;
    }
    return true;
}

bool import_plugin_data(const wchar_t* folder, std::wstring& error) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_store || !g_store->is_open()) { error = L"学習DBが初期化されていません。"; return false; }
    const std::filesystem::path dir(folder);
    const auto incoming_db = dir / L"training.sqlite3";
    const auto incoming_ini = dir / L"settings.ini";
    if (!std::filesystem::is_regular_file(incoming_db) || !std::filesystem::is_regular_file(incoming_ini)) {
        error = L"選択フォルダーに training.sqlite3 または settings.ini がありません。";
        return false;
    }
    const auto rollback_db = g_data_dir / L"training.import-rollback.sqlite3";
    const auto rollback_ini = g_data_dir / L"settings.import-rollback.ini";
    std::string rollback_utf8, incoming_utf8;
    if (!wide_path_to_utf8(rollback_db, rollback_utf8) || !wide_path_to_utf8(incoming_db, incoming_utf8)) {
        error = L"ファイルパスを変換できません。"; return false;
    }
    std::string db_error;
    if (!g_store->backup_to(rollback_utf8, &db_error)) {
        error = L"現在の学習DBを退避できません。"; return false;
    }
    if (!CopyFileW((g_data_dir / L"settings.ini").c_str(), rollback_ini.c_str(), FALSE)) {
        DeleteFileW(rollback_db.c_str());
        error = L"現在の設定を退避できません。"; return false;
    }
    // Drop the model before replacing the database so no cached training state survives.
    g_pipeline.reset();
    if (!g_store->restore_from(incoming_utf8, &db_error)) {
        g_pipeline = std::make_unique<beckyas::MailPipeline>(*g_store);
        g_pipeline->initialize(nullptr);
        DeleteFileW(rollback_db.c_str()); DeleteFileW(rollback_ini.c_str());
        error = L"学習DBをインポートできません: " + utf8_to_wide(db_error);
        return false;
    }
    if (!CopyFileW(incoming_ini.c_str(), (g_data_dir / L"settings.ini").c_str(), FALSE)) {
        g_store->restore_from(rollback_utf8, nullptr);
        CopyFileW(rollback_ini.c_str(), (g_data_dir / L"settings.ini").c_str(), FALSE);
        DeleteFileW(rollback_db.c_str()); DeleteFileW(rollback_ini.c_str());
        error = L"設定ファイルを反映できなかったため、元のデータに戻しました。";
        return false;
    }
    g_log_settings.enabled = GetPrivateProfileIntW(L"logging", L"enabled", 1,
        (g_data_dir / L"settings.ini").c_str()) != 0;
    g_log_settings.test_mode = GetPrivateProfileIntW(L"test_mode", L"enabled", 0,
        (g_data_dir / L"settings.ini").c_str()) != 0;
    g_pipeline = std::make_unique<beckyas::MailPipeline>(*g_store);
    if (!g_pipeline->initialize(&db_error)) {
        g_pipeline.reset();
        g_store->restore_from(rollback_utf8, nullptr);
        CopyFileW(rollback_ini.c_str(), (g_data_dir / L"settings.ini").c_str(), FALSE);
        g_log_settings.enabled = GetPrivateProfileIntW(L"logging", L"enabled", 1,
            (g_data_dir / L"settings.ini").c_str()) != 0;
        g_log_settings.test_mode = GetPrivateProfileIntW(L"test_mode", L"enabled", 0,
            (g_data_dir / L"settings.ini").c_str()) != 0;
        g_pipeline = std::make_unique<beckyas::MailPipeline>(*g_store);
        g_pipeline->initialize(nullptr);
        DeleteFileW(rollback_db.c_str()); DeleteFileW(rollback_ini.c_str());
        error = L"インポート後の初期化に失敗したため、元のデータに戻しました。";
        return false;
    }
    DeleteFileW(rollback_db.c_str()); DeleteFileW(rollback_ini.c_str());
    return true;
}

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
    if (action) *action = -1;
    if (parameter) *parameter = nullptr;
    if (!message) return 0;
    try {
        const auto length = strnlen_s(message, kMaxMessageBytes + 1);
        if (length == 0 || length > kMaxMessageBytes) {
            operational_log("WARN", "message skipped: empty or size limit exceeded");
            test_log("WARN", "filter input rejected by size guard");
            return 0;
        }
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_pipeline && !initialize_plugin()) {
            operational_log("ERROR", "pipeline unavailable; message passed to standard filter");
            return 0;
        }
        test_log("TRACE", "filter callback entered; bytes=" + std::to_string(length));
        beckyas::ParsedMail parsed;
        beckyas::Result result;
        std::string error;
        if (!g_pipeline->analyze(std::string(message, length), parsed, result, &error)) {
            operational_log("ERROR", "analysis failed: " + error);
            test_log("ERROR", "parser/pipeline error: " + error);
            return 0;
        }
        const char* verdict = result.verdict == beckyas::Verdict::Spam ? "spam" :
            result.verdict == beckyas::Verdict::Review ? "review" : "ham";
        operational_log("INFO", std::string("classification verdict=") + verdict +
            " score=" + std::to_string(result.score));
        if (g_log_settings.test_mode) {
            test_log("TRACE", "parsed bytes=" + std::to_string(parsed.source_bytes) +
                " mime_parts=" + std::to_string(parsed.mime_parts) +
                " headers=" + std::to_string(parsed.headers.size()) +
                " attachments=" + std::to_string(parsed.attachments.size()) +
                " body_truncated=" + (parsed.body_truncated ? "true" : "false"));
            test_log("TRACE", std::string("result verdict=") + verdict +
                " score=" + std::to_string(result.score) +
                " bayes_probability=" + std::to_string(result.bayes_probability) +
                " findings=" + std::to_string(result.findings.size()) +
                " spam_samples=" + std::to_string(g_pipeline->model().spam_samples()) +
                " ham_samples=" + std::to_string(g_pipeline->model().ham_samples()) +
                " vocabulary=" + std::to_string(g_pipeline->model().vocabulary_size()));
            for (const auto& finding : result.findings)
                test_log("RULE", "rule=" + finding.rule + " score=" +
                    std::to_string(finding.score) + " reason=" + finding.reason);
            for (const auto& warning : parsed.warnings)
                test_log("WARN", "parser warning: " + warning);
        }
    } catch (...) {
        operational_log("ERROR", "unexpected exception in filter callback");
        test_log("ERROR", "unexpected exception in filter callback");
    }
    // Audit only. No mail move or delete; continue normal Becky! filtering.
    return 0;
}
}
