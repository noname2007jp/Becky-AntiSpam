#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>

#include "mail_pipeline.hpp"
#include "sqlite_store.hpp"
#include "tokenizer.hpp"
#include "data_paths.hpp"

#include <cstdio>
#include <fstream>
#include <vector>
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
BeckyAllocFn g_becky_alloc = nullptr;
constexpr int kActionAddHeader = 8;
constexpr int kFilterPass = 1;
constexpr char kClassificationHeader[] = "x-antispam-classification";

std::size_t diagnostic_url_count(const std::string& text) {
    std::size_t count = 0;
    for (std::size_t i = 0; i < text.size();) {
        const auto lower_at = [&text](std::size_t pos, const char* token) {
            const std::size_t n = std::char_traits<char>::length(token);
            if (pos + n > text.size()) return false;
            for (std::size_t j = 0; j < n; ++j) {
                const auto c = static_cast<unsigned char>(text[pos + j]);
                if (static_cast<char>(std::tolower(c)) != token[j]) return false;
            }
            return true;
        };
        if (lower_at(i, "https://")) { ++count; i += 8; }
        else if (lower_at(i, "http://")) { ++count; i += 7; }
        else if (lower_at(i, "www.")) { ++count; i += 4; }
        else ++i;
    }
    return count;
}

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
    if (!g_log_settings.enabled || !g_log_settings.test_mode) return;

    // Keep the dedicated diagnostic file, but also mirror diagnostics to the
    // operational log so they remain visible if test-detail.log cannot be opened.
    log_line(g_debug_log, level, message, kTestLogLimit);
    log_line(g_audit_log, level, std::string("[TEST] ") + message, kDefaultLogLimit);
}

bool initialize_plugin() {
    // Becky! SDK: BKA_Alloc allocates callback-lifetime memory for filter parameters.
    const auto becky_module = GetModuleHandleW(nullptr);
    g_becky_alloc = becky_module
        ? reinterpret_cast<BeckyAllocFn>(GetProcAddress(becky_module, "BKA_Alloc"))
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

    // UTF-8 rules: aliases separated by ';', then '|', then allowed domains separated by ';'.
    // Create a starter file only when absent; never overwrite user edits.
    const auto brand_file = g_data_dir / L"brand-domains.txt";
    if (!std::filesystem::exists(brand_file)) {
        std::ofstream seed(brand_file, std::ios::binary);
        if (seed) {
            seed << "# alias1;alias2|allowed-domain1;allowed-domain2\n"
                 << "American Express;AmericanExpress;アメリカン・エキスプレス;アメックス|americanexpress.com\n";
        }
    }
    std::vector<beckyas::BrandRule> brand_rules;
    {
        std::ifstream input(brand_file, std::ios::binary);
        std::string line;
        while (std::getline(input, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty() || line[0] == '#') continue;
            const auto separator = line.find('|');
            if (separator == std::string::npos) continue;
            beckyas::BrandRule rule;
            auto parse_list = [](const std::string& value, std::vector<std::string>& out) {
                std::size_t start = 0;
                while (start <= value.size()) {
                    const auto end = value.find(';', start);
                    auto item = value.substr(start, end == std::string::npos ? end : end - start);
                    const auto first = item.find_first_not_of(" \t");
                    const auto last = item.find_last_not_of(" \t");
                    if (first != std::string::npos) out.push_back(item.substr(first, last - first + 1));
                    if (end == std::string::npos) break;
                    start = end + 1;
                }
            };
            parse_list(line.substr(0, separator), rule.aliases);
            parse_list(line.substr(separator + 1), rule.allowed_domains);
            if (!rule.aliases.empty() && !rule.allowed_domains.empty())
                brand_rules.push_back(std::move(rule));
        }
    }

    const auto ini = g_data_dir / L"settings.ini";
    g_log_settings.enabled = GetPrivateProfileIntW(L"logging", L"enabled", 1, ini.c_str()) != 0;
    g_log_settings.test_mode = GetPrivateProfileIntW(L"test_mode", L"enabled", 0, ini.c_str()) != 0;
    operational_log("INFO", std::string("startup logging=") +
        (g_log_settings.enabled ? "on" : "off") + " test_mode=" +
        (g_log_settings.test_mode ? "on" : "off"));

    g_store = std::make_unique<beckyas::SqliteStore>(db_utf8);
    beckyas::Settings classifier_settings;
    classifier_settings.brand_rules = std::move(brand_rules);
    g_pipeline = std::make_unique<beckyas::MailPipeline>(*g_store, classifier_settings);
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

        // Detailed diagnostics intentionally contain classifier metadata only.
        // Never log sender, subject, headers, body, tokens, or raw message data.
        const char* verdict_name = result.verdict == beckyas::Verdict::Spam ? "Spam" :
            result.verdict == beckyas::Verdict::Review ? "Review" : "Ham";
        const auto& model = g_pipeline->model();
        const auto bayes_percent = static_cast<int>(
            result.bayes_probability * 100.0 + 0.5);
        const auto parsed_url_count = diagnostic_url_count(
            parsed.message.subject + "\n" + parsed.message.headers + "\n" + parsed.message.body);
        test_log("INFO", std::string("parse-metadata source_bytes=") +
            std::to_string(parsed.source_bytes) +
            " header_count=" + std::to_string(parsed.headers.size()) +
            " subject_bytes=" + std::to_string(parsed.message.subject.size()) +
            " classifier_header_bytes=" + std::to_string(parsed.message.headers.size()) +
            " body_bytes=" + std::to_string(parsed.message.body.size()) +
            " url_count=" + std::to_string(parsed_url_count) +
            " mime_parts=" + std::to_string(parsed.mime_parts) +
            " attachments=" + std::to_string(parsed.attachments.size()) +
            " warnings=" + std::to_string(parsed.warnings.size()) +
            " body_truncated=" + std::string(parsed.body_truncated ? "yes" : "no"));
        for (const auto& warning : parsed.warnings) {
            test_log("WARN", std::string("parse-warning ") + warning);
        }
        test_log("INFO", std::string("classification verdict=") + verdict_name +
            " score=" + std::to_string(result.score) +
            " bayes_probability=" + std::to_string(bayes_percent) + "%" +
            " ham_samples=" + std::to_string(model.ham_samples()) +
            " spam_samples=" + std::to_string(model.spam_samples()) +
            " findings=" + std::to_string(result.findings.size()));
        for (const auto& finding : result.findings) {
            test_log("INFO", std::string("finding rule=") + finding.rule +
                " score=" + (finding.score >= 0 ? "+" : "") +
                std::to_string(finding.score) +
                " reason=" + finding.reason);
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
        const std::string header = std::string("X-AntiSpam-Classification: ") + label;
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
    // The SDK calls this after a message has been retrieved and saved.
    // ACTION_ADDHEADER is the supported way to add incoming headers before
    // Becky! applies its normal filtering and saves the message. Do not
    // rewrite the stored source here: SetSource has no return value and the
    // previous post-retrieve rewrite was not verifiably persistent.
    if (!message || !mail_id || !*mail_id) {
        operational_log("WARN", "retrieve callback missing message or mail ID");
        return 0;
    }
    // Verify the field only in the RFC 5322 header block. A substring in
    // the message body must not be counted as a successful header insertion.
    const char* header_end = std::strstr(message, "\r\n\r\n");
    const char* marker = "X-AntiSpam-Classification:";
    const char* found = std::strstr(message, marker);
    const bool observed = header_end && found && found < header_end &&
        (found == message || (found >= message + 2 && found[-2] == '\r' && found[-1] == '\n'));
    operational_log(observed ? "INFO" : "WARN",
        std::string("retrieve callback classification header in header-block=") +
        (observed ? "yes" : "no"));
    return 0;
}

int WINAPI BKC_OnFinishRetrieve(int message_count) {
    operational_log("INFO", std::string("retrieve session finished messages=") +
        std::to_string(message_count));
    return 0;
}

int WINAPI BKC_OnOpenMail(LPCSTR) {
    return 0;
}

int WINAPI BKC_OnEveryMinute() {
    return 0;
}
}
