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
#include <utility>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <algorithm>
#include <cctype>
#include <unordered_map>
#include <array>
#include <chrono>

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
std::filesystem::path g_data_dir, g_audit_log, g_debug_log, g_summary_log;
std::uint64_t g_test_case_sequence = 0;
LogSettings g_log_settings;
bool g_evaluation_enabled = true;
using BeckyAllocFn = LPVOID (WINAPI*)(DWORD);
BeckyAllocFn g_becky_alloc = nullptr;
using BeckyGetWindowHandlesFn = BOOL (WINAPI*)(HWND*, HWND*, HWND*, HWND*);
using BeckyGetNextMailFn = int (WINAPI*)(int, LPSTR, int, BOOL);
using BeckyGetSourceFn = LPSTR (WINAPI*)(LPCSTR);
using BeckyFreeFn = void (WINAPI*)(LPVOID);
using BeckyRegisterCommandFn = UINT (WINAPI*)(LPCSTR, int, void (CALLBACK*)(HWND, LPARAM));
BeckyGetWindowHandlesFn g_becky_get_windows = nullptr;
BeckyGetNextMailFn g_becky_get_next_mail = nullptr;
BeckyGetSourceFn g_becky_get_source = nullptr;
BeckyFreeFn g_becky_free = nullptr;
BeckyRegisterCommandFn g_becky_register_command = nullptr;
int g_ham_key = 'H';
int g_spam_key = 'S';
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

void test_log_case(const char* level, std::uint64_t case_number,
                  const std::string& message) noexcept {
    if (!g_log_settings.enabled || !g_log_settings.test_mode) return;
    test_log(level, std::string("case=") + std::to_string(case_number) + " " + message);
}

bool initialize_plugin() {
    // Becky! SDK: BKA_Alloc allocates callback-lifetime memory for filter parameters.
    const auto becky_module = GetModuleHandleW(nullptr);
    g_becky_alloc = becky_module
        ? reinterpret_cast<BeckyAllocFn>(GetProcAddress(becky_module, "BKA_Alloc"))
        : nullptr;
    g_becky_get_windows = becky_module
        ? reinterpret_cast<BeckyGetWindowHandlesFn>(GetProcAddress(becky_module, "BKA_GetWindowHandles"))
        : nullptr;
    g_becky_get_next_mail = becky_module
        ? reinterpret_cast<BeckyGetNextMailFn>(GetProcAddress(becky_module, "BKA_GetNextMail"))
        : nullptr;
    g_becky_get_source = becky_module
        ? reinterpret_cast<BeckyGetSourceFn>(GetProcAddress(becky_module, "BKA_GetSource"))
        : nullptr;
    g_becky_free = becky_module
        ? reinterpret_cast<BeckyFreeFn>(GetProcAddress(becky_module, "BKA_Free"))
        : nullptr;
    g_becky_register_command = becky_module
        ? reinterpret_cast<BeckyRegisterCommandFn>(GetProcAddress(becky_module, "BKA_RegisterCommand"))
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
    g_summary_log = g_data_dir / L"test-summary.log";

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
        bool first_line = true;
        while (std::getline(input, line)) {
            if (first_line && line.size() >= 3 &&
                static_cast<unsigned char>(line[0]) == 0xEF &&
                static_cast<unsigned char>(line[1]) == 0xBB &&
                static_cast<unsigned char>(line[2]) == 0xBF) line.erase(0, 3);
            first_line = false;
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
    wchar_t ham_key[8] = L"H", spam_key[8] = L"S";
    GetPrivateProfileStringW(L"review", L"ham_key", L"H", ham_key, 8, ini.c_str());
    GetPrivateProfileStringW(L"review", L"spam_key", L"S", spam_key, 8, ini.c_str());
    g_ham_key = (ham_key[0] >= L'a' && ham_key[0] <= L'z')
        ? ham_key[0] - L'a' + L'A' : ham_key[0];
    g_spam_key = (spam_key[0] >= L'a' && spam_key[0] <= L'z')
        ? spam_key[0] - L'a' + L'A' : spam_key[0];
    g_log_settings.enabled = GetPrivateProfileIntW(L"logging", L"enabled", 1, ini.c_str()) != 0;
    g_log_settings.test_mode = GetPrivateProfileIntW(L"test_mode", L"enabled", 0, ini.c_str()) != 0;
    g_evaluation_enabled = GetPrivateProfileIntW(L"evaluation", L"enabled", 1, ini.c_str()) != 0;
    if (g_log_settings.test_mode && g_test_case_sequence == 0) {
        // Keep case numbers unique across plugin restarts while remaining numeric
        // and compact enough for the summary and evaluation logs.
        const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        g_test_case_sequence = static_cast<std::uint64_t>(now_ms) * 1000u;
    }
    operational_log("INFO", std::string("startup logging=") +
        (g_log_settings.enabled ? "on" : "off") + " test_mode=" +
        (g_log_settings.test_mode ? "on" : "off") + " evaluation=" +
        (g_evaluation_enabled ? "on" : "off"));

    g_store = std::make_unique<beckyas::SqliteStore>(db_utf8);
    beckyas::Settings classifier_settings;
    classifier_settings.brand_rules = std::move(brand_rules);
    classifier_settings.enable_bayes_comparison = g_log_settings.test_mode;
    classifier_settings.enable_symbol_comparison = g_log_settings.test_mode;
    operational_log("INFO", std::string("brand rules loaded count=") +
        std::to_string(classifier_settings.brand_rules.size()));
    g_pipeline = std::make_unique<beckyas::MailPipeline>(*g_store, classifier_settings);
    std::string error;
    if (!g_pipeline->initialize(&error)) {
        operational_log("ERROR", "initialization failed: " + error);
        g_pipeline.reset(); g_store.reset(); return false;
    }
    operational_log("INFO", "pipeline initialized");
    return true;
}


void train_selected_messages(bool spam, const char* trigger) {
    try {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_pipeline && !initialize_plugin()) {
            operational_log("ERROR", "manual training skipped: pipeline unavailable");
            return;
        }
        if (!g_becky_get_next_mail || !g_becky_get_source || !g_becky_free) {
            operational_log("ERROR", "manual training skipped: Becky! mail APIs unavailable");
            return;
        }

        std::size_t selected = 0, trained = 0, reclassified = 0, duplicate = 0, failed = 0;
        int position = -1;
        for (std::size_t guard = 0; guard < 10000; ++guard) {
            std::array<char, 1024> mail_id{};
            const int next = g_becky_get_next_mail(position, mail_id.data(),
                                                   static_cast<int>(mail_id.size()), TRUE);
            if (next == -1) break;
            position = next;
            if (mail_id[0] == '\0') { ++failed; continue; }
            ++selected;

            LPSTR source = g_becky_get_source(mail_id.data());
            if (!source) { ++failed; continue; }
            const void* terminator = std::memchr(source, '\0', kMaxMessageBytes + 1);
            if (!terminator) {
                g_becky_free(source);
                ++failed;
                continue;
            }
            std::string raw(source, static_cast<const char*>(terminator) - source);
            g_becky_free(source);

            std::string error;
            const auto status = g_pipeline->train(raw, spam, nullptr, &error);
            switch (status) {
            case beckyas::TrainStatus::Trained: ++trained; break;
            case beckyas::TrainStatus::Reclassified: ++reclassified; break;
            case beckyas::TrainStatus::Duplicate: ++duplicate; break;
            case beckyas::TrainStatus::Error: ++failed; break;
            }
        }

        const char* label = spam ? "spam" : "ham";
        operational_log("INFO", std::string("manual training trigger=") + trigger +
            " label=" + label +
            " selected=" + std::to_string(selected) +
            " trained=" + std::to_string(trained) +
            " reclassified=" + std::to_string(reclassified) +
            " duplicate=" + std::to_string(duplicate) +
            " failed=" + std::to_string(failed));

        beckyas::EvaluationStats evaluation;
        std::string evaluation_error;
        if (g_pipeline->get_evaluation_stats(evaluation, &evaluation_error)) {
            operational_log("INFO", std::string("evaluation metrics pending=") +
                std::to_string(evaluation.pending) +
                " labeled=" + std::to_string(evaluation.labeled) +
                " spam_as_ham=" + std::to_string(evaluation.spam_as_ham) +
                " spam_as_review=" + std::to_string(evaluation.spam_as_review) +
                " spam_as_spam=" + std::to_string(evaluation.spam_as_spam) +
                " ham_as_ham=" + std::to_string(evaluation.ham_as_ham) +
                " ham_as_review=" + std::to_string(evaluation.ham_as_review) +
                " ham_as_spam=" + std::to_string(evaluation.ham_as_spam) +
                " symbol_labeled=" + std::to_string(evaluation.symbol_labeled) +
                " symbol_spam_as_ham=" + std::to_string(evaluation.symbol_spam_as_ham) +
                " symbol_spam_as_review=" + std::to_string(evaluation.symbol_spam_as_review) +
                " symbol_spam_as_spam=" + std::to_string(evaluation.symbol_spam_as_spam) +
                " symbol_ham_as_ham=" + std::to_string(evaluation.symbol_ham_as_ham) +
                " symbol_ham_as_review=" + std::to_string(evaluation.symbol_ham_as_review) +
                " symbol_ham_as_spam=" + std::to_string(evaluation.symbol_ham_as_spam));
        } else {
            operational_log("WARN", "evaluation metrics unavailable: " + evaluation_error);
        }
    } catch (...) {
        operational_log("ERROR", std::string("manual training callback failed trigger=") + trigger);
    }
}

void CALLBACK menu_train_ham(HWND, LPARAM) {
    train_selected_messages(false, "context-menu");
}
void CALLBACK menu_train_spam(HWND, LPARAM) {
    train_selected_messages(true, "context-menu");
}

void label_selected_messages(bool spam, const char* trigger) {
    try {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_pipeline && !initialize_plugin()) {
            operational_log("ERROR", "evaluation labeling skipped: pipeline unavailable");
            return;
        }
        if (!g_becky_get_next_mail || !g_becky_get_source || !g_becky_free) {
            operational_log("ERROR", "evaluation labeling skipped: Becky! mail APIs unavailable");
            return;
        }

        std::size_t selected = 0, labeled = 0, unmatched = 0, failed = 0;
        int position = -1;
        for (std::size_t guard = 0; guard < 10000; ++guard) {
            std::array<char, 1024> mail_id{};
            const int next = g_becky_get_next_mail(position, mail_id.data(),
                                                   static_cast<int>(mail_id.size()), TRUE);
            if (next == -1) break;
            position = next;
            if (mail_id[0] == '\0') { ++failed; continue; }
            ++selected;

            LPSTR source = g_becky_get_source(mail_id.data());
            if (!source) { ++failed; continue; }
            const void* terminator = std::memchr(source, '\0', kMaxMessageBytes + 1);
            if (!terminator) {
                g_becky_free(source);
                ++failed;
                continue;
            }
            std::string raw(source, static_cast<const char*>(terminator) - source);
            g_becky_free(source);

            std::string error;
            bool matched = false;
            beckyas::EvaluationRecord evaluation_record;
            if (!g_pipeline->label_evaluation(raw, spam, &matched, &error,
                                               &evaluation_record)) {
                ++failed;
                continue;
            }
            if (matched) {
                ++labeled;
                // Correlate only anonymous test case numbers with the confirmed
                // label and saved comparison verdicts. Never log message identity.
                if (evaluation_record.case_number > 0) {
                    const auto verdict_name = [](beckyas::Verdict verdict) {
                        return verdict == beckyas::Verdict::Spam ? "Spam" :
                            verdict == beckyas::Verdict::Review ? "Review" : "Ham";
                    };
                    operational_log("INFO",
                        std::string("evaluation-case case=") +
                        std::to_string(evaluation_record.case_number) +
                        " actual=" + (spam ? "Spam" : "Ham") +
                        " active=" + verdict_name(evaluation_record.predicted_verdict) +
                        " symbol_v1=" + (evaluation_record.comparison_available
                            ? verdict_name(evaluation_record.comparison_verdict) : "NA") +
                        " symbol_v2=" + (evaluation_record.comparison_v2_available
                            ? verdict_name(evaluation_record.comparison_v2_verdict) : "NA"));
                }
            } else {
                ++unmatched;
            }
        }

        operational_log("INFO", std::string("evaluation label trigger=") + trigger +
            " label=" + (spam ? "spam" : "ham") +
            " selected=" + std::to_string(selected) +
            " labeled=" + std::to_string(labeled) +
            " no_prediction=" + std::to_string(unmatched) +
            " failed=" + std::to_string(failed) +
            " training=none");

        beckyas::EvaluationStats evaluation;
        std::string evaluation_error;
        if (g_pipeline->get_evaluation_stats(evaluation, &evaluation_error)) {
            operational_log("INFO", std::string("evaluation metrics pending=") +
                std::to_string(evaluation.pending) +
                " labeled=" + std::to_string(evaluation.labeled) +
                " spam_as_ham=" + std::to_string(evaluation.spam_as_ham) +
                " spam_as_review=" + std::to_string(evaluation.spam_as_review) +
                " spam_as_spam=" + std::to_string(evaluation.spam_as_spam) +
                " ham_as_ham=" + std::to_string(evaluation.ham_as_ham) +
                " ham_as_review=" + std::to_string(evaluation.ham_as_review) +
                " ham_as_spam=" + std::to_string(evaluation.ham_as_spam));
        } else {
            operational_log("WARN", "evaluation metrics unavailable: " + evaluation_error);
        }
    } catch (...) {
        operational_log("ERROR", std::string("evaluation labeling callback failed trigger=") + trigger);
    }
}

void CALLBACK menu_evaluate_ham(HWND, LPARAM) {
    label_selected_messages(false, "context-menu");
}
void CALLBACK menu_evaluate_spam(HWND, LPARAM) {
    label_selected_messages(true, "context-menu");
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
int WINAPI BKC_OnMenuInit(HWND, HMENU menu, int type) {
    // BKC_MENU_LISTVIEW (1) is the mail-list context menu.
    if (type != 1 || !menu) return 0;

    // BKC_OnMenuInit can be called before BKC_OnStart. Resolve this API here
    // as well, rather than relying on plugin initialization order.
    if (!g_becky_register_command) {
        const auto becky_module = GetModuleHandleW(nullptr);
        g_becky_register_command = becky_module
            ? reinterpret_cast<BeckyRegisterCommandFn>(
                GetProcAddress(becky_module, "BKA_RegisterCommand"))
            : nullptr;
    }
    if (!g_becky_register_command) return 0;

    const UINT ham_id = g_becky_register_command(
        "Train selected messages as Ham", type, menu_train_ham);
    const UINT spam_id = g_becky_register_command(
        "Train selected messages as Spam", type, menu_train_spam);
    const UINT eval_ham_id = g_becky_register_command(
        "Record selected messages as Ham (no training)", type, menu_evaluate_ham);
    const UINT eval_spam_id = g_becky_register_command(
        "Record selected messages as Spam (no training)", type, menu_evaluate_spam);

    if (!ham_id && !spam_id && !eval_ham_id && !eval_spam_id) return 0;
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    if (ham_id) {
        const std::wstring label = std::wstring(L"正常メールとして学習 (") +
            static_cast<wchar_t>(g_ham_key) + L")";
        AppendMenuW(menu, MF_STRING, static_cast<UINT_PTR>(ham_id), label.c_str());
    }
    if (spam_id) {
        const std::wstring label = std::wstring(L"迷惑メールとして学習 (") +
            static_cast<wchar_t>(g_spam_key) + L")";
        AppendMenuW(menu, MF_STRING, static_cast<UINT_PTR>(spam_id), label.c_str());
    }
    if (eval_ham_id || eval_spam_id) AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    if (eval_ham_id)
        AppendMenuW(menu, MF_STRING, static_cast<UINT_PTR>(eval_ham_id),
                    L"評価用：正常メールとして記録（学習しない）");
    if (eval_spam_id)
        AppendMenuW(menu, MF_STRING, static_cast<UINT_PTR>(eval_spam_id),
                    L"評価用：迷惑メールとして記録（学習しない）");
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

        // Assign one sequential test case number before writing any per-message
        // diagnostics so test-detail.log and test-summary.log can be correlated.
        const std::uint64_t test_case_number =
            (g_log_settings.enabled && g_log_settings.test_mode)
                ? ++g_test_case_sequence : 0;

        // Detailed diagnostics intentionally contain classifier metadata only.
        // Never log sender, subject, headers, body, tokens, or raw message data.
        const char* verdict_name = result.verdict == beckyas::Verdict::Spam ? "Spam" :
            result.verdict == beckyas::Verdict::Review ? "Review" : "Ham";
        const auto& model = g_pipeline->model();
        const auto bayes_percent = static_cast<int>(
            result.bayes_probability * 100.0 + 0.5);
        const auto parsed_url_count = diagnostic_url_count(
            parsed.message.subject + "\n" + parsed.message.headers + "\n" + parsed.message.body);
        test_log_case("INFO", test_case_number, std::string("parse-metadata source_bytes=") +
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
            test_log_case("WARN", test_case_number, std::string("parse-warning ") + warning);
        }
        test_log_case("INFO", test_case_number, std::string("brand-match rules_checked=") +
            std::to_string(result.brand_rules_checked) +
            " matched=" + (result.brand_rule_matched ? "yes" : "no") +
            " subject_match=" + (result.brand_subject_match ? "yes" : "no") +
            " display_match=" + (result.brand_display_match ? "yes" : "no") +
            " from_domain_present=" + (result.brand_from_domain_present ? "yes" : "no") +
            " from_allowed=" + (result.brand_from_allowed ? "yes" : "no") +
            " url_hosts_checked=" + std::to_string(result.brand_url_hosts_checked) +
            " url_domain_mismatch=" + (result.brand_url_domain_mismatch ? "yes" : "no"));
        test_log_case("INFO", test_case_number, std::string("classification verdict=") + verdict_name +
            " score=" + std::to_string(result.score) +
            " bayes_probability=" + std::to_string(bayes_percent) + "%" +
            " bayes_tokens=" + std::to_string(result.bayes_diagnostics.total_tokens) +
            " bayes_known_tokens=" + std::to_string(result.bayes_diagnostics.known_tokens) +
            " bayes_unknown_tokens=" + std::to_string(result.bayes_diagnostics.unknown_tokens) +
            " bayes_spam_evidence=" + std::to_string(result.bayes_diagnostics.spam_evidence_tokens) +
            " bayes_ham_evidence=" + std::to_string(result.bayes_diagnostics.ham_evidence_tokens) +
            " bayes_log_odds=" + std::to_string(result.bayes_diagnostics.log_odds) +
            " bayes_bernoulli_probability=" +
                std::to_string(static_cast<int>(result.bayes_comparison.bernoulli_probability * 100.0 + 0.5)) + "%" +
            " bayes_bernoulli_log_odds=" +
                std::to_string(result.bayes_comparison.bernoulli_log_odds) +
            " bayes_bernoulli_present_features=" +
                std::to_string(result.bayes_comparison.bernoulli_present_features) +
            " bayes_bernoulli_absent_features=" +
                std::to_string(result.bayes_comparison.bernoulli_absent_features) +
            " bayes_bernoulli_present_log_odds=" +
                std::to_string(result.bayes_comparison.bernoulli_present_log_odds) +
            " bayes_bernoulli_absent_log_odds=" +
                std::to_string(result.bayes_comparison.bernoulli_absent_log_odds) +
            " bayes_corr_probability=" +
                std::to_string(static_cast<int>(
                    result.bayes_comparison.correlation_adjusted_probability * 100.0 + 0.5)) + "%" +
            " bayes_corr_log_odds=" +
                std::to_string(result.bayes_comparison.correlation_adjusted_log_odds) +
            " bayes_corr_evidence_log_odds=" +
                std::to_string(result.bayes_comparison.correlation_adjusted_evidence_log_odds) +
            " bayes_corr_features=" +
                std::to_string(result.bayes_comparison.correlation_adjusted_features) +
            " bayes_corr_scale=" +
                std::to_string(result.bayes_comparison.correlation_adjustment_scale) +
            " bayes_vocabulary_features=" +
                std::to_string(result.bayes_comparison.vocabulary_features) +
            " ham_samples=" + std::to_string(model.ham_samples()) +
            " spam_samples=" + std::to_string(model.spam_samples()) +
            " findings=" + std::to_string(result.findings.size()) +
            " symbol_score=" + std::to_string(result.symbol_comparison.score) +
            " symbol_auth=" + std::to_string(result.symbol_comparison.authentication_score) +
            " symbol_header=" + std::to_string(result.symbol_comparison.header_score) +
            " symbol_brand=" + std::to_string(result.symbol_comparison.brand_score) +
            " symbol_content=" + std::to_string(result.symbol_comparison.content_score) +
            " symbol_url=" + std::to_string(result.symbol_comparison.url_score) +
            " symbol_bayes=" + std::to_string(result.symbol_comparison.bayes_score) +
            " symbol_count=" + std::to_string(result.symbol_comparison.symbol_count) +
            " symbol_verdict=" + (result.symbol_comparison.verdict == beckyas::Verdict::Spam
                ? "Spam" : result.symbol_comparison.verdict == beckyas::Verdict::Review
                ? "Review" : "Ham") +
            " symbol_v2_score=" + std::to_string(result.symbol_experiment.score) +
            " symbol_v2_content=" + std::to_string(result.symbol_experiment.content_score) +
            " symbol_v2_url=" + std::to_string(result.symbol_experiment.url_score) +
            " symbol_v2_bayes=" + std::to_string(result.symbol_experiment.bayes_score) +
            " symbol_v2_verdict=" + (result.symbol_experiment.verdict == beckyas::Verdict::Spam
                ? "Spam" : result.symbol_experiment.verdict == beckyas::Verdict::Review
                ? "Review" : "Ham"));
        // One compact, privacy-safe record per analyzed message for sharing.
        // Do not include message IDs, addresses, domains, subjects, URLs, or tokens.
        if (g_log_settings.enabled && g_log_settings.test_mode) {
            const auto corr_percent = static_cast<int>(
                result.bayes_comparison.correlation_adjusted_probability * 100.0 + 0.5);
            const auto bernoulli_percent = static_cast<int>(
                result.bayes_comparison.bernoulli_probability * 100.0 + 0.5);
            const char* symbol_verdict = result.symbol_comparison.verdict == beckyas::Verdict::Spam
                ? "Spam" : result.symbol_comparison.verdict == beckyas::Verdict::Review
                ? "Review" : "Ham";
            const char* symbol_v2_verdict = result.symbol_experiment.verdict == beckyas::Verdict::Spam
                ? "Spam" : result.symbol_experiment.verdict == beckyas::Verdict::Review
                ? "Review" : "Ham";
            log_line(g_summary_log, "SUMMARY",
                std::string("format=1 case=") + std::to_string(test_case_number) +
                " verdict=" + verdict_name +
                " score=" + std::to_string(result.score) +
                " bayes=" + std::to_string(bayes_percent) +
                " bayes_tokens=" + std::to_string(result.bayes_diagnostics.total_tokens) +
                " bayes_known=" + std::to_string(result.bayes_diagnostics.known_tokens) +
                " bayes_unknown=" + std::to_string(result.bayes_diagnostics.unknown_tokens) +
                " bayes_bernoulli=" + std::to_string(bernoulli_percent) +
                " bayes_corr=" + std::to_string(corr_percent) +
                " bayes_corr_evidence=" + std::to_string(result.bayes_comparison.correlation_adjusted_evidence_log_odds) +
                " bayes_corr_features=" + std::to_string(result.bayes_comparison.correlation_adjusted_features) +
                " symbol_score=" + std::to_string(result.symbol_comparison.score) +
                " symbol_verdict=" + symbol_verdict +
                " symbol_auth=" + std::to_string(result.symbol_comparison.authentication_score) +
                " symbol_header=" + std::to_string(result.symbol_comparison.header_score) +
                " symbol_brand=" + std::to_string(result.symbol_comparison.brand_score) +
                " symbol_content=" + std::to_string(result.symbol_comparison.content_score) +
                " symbol_url=" + std::to_string(result.symbol_comparison.url_score) +
                " symbol_bayes=" + std::to_string(result.symbol_comparison.bayes_score) +
                " symbol_v2_score=" + std::to_string(result.symbol_experiment.score) +
                " symbol_v2_verdict=" + symbol_v2_verdict +
                " symbol_v2_content=" + std::to_string(result.symbol_experiment.content_score) +
                " symbol_v2_url=" + std::to_string(result.symbol_experiment.url_score) +
                " symbol_v2_bayes=" + std::to_string(result.symbol_experiment.bayes_score) +
                " symbols=" + std::to_string(result.symbol_comparison.symbol_count) +
                " findings=" + std::to_string(result.findings.size()) +
                " urls=" + std::to_string(parsed_url_count) +
                " mime_parts=" + std::to_string(parsed.mime_parts) +
                " attachments=" + std::to_string(parsed.attachments.size()) +
                " parse_warnings=" + std::to_string(parsed.warnings.size()) +
                " ham_samples=" + std::to_string(model.ham_samples()) +
                " spam_samples=" + std::to_string(model.spam_samples()),
                kTestLogLimit);
        }
        for (const auto& finding : result.findings) {
            test_log_case("INFO", test_case_number, std::string("finding rule=") + finding.rule +
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

        // Store only a one-way hash and prediction metadata; no message content is retained.
        // This capture is independent from diagnostic test logging and Bayes training.
        if (g_evaluation_enabled &&
            !g_pipeline->record_prediction(source, result, &error,
                                           g_log_settings.test_mode,
                                           test_case_number)) {
            operational_log("WARN", "evaluation prediction not stored: " + error);
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

int WINAPI BKC_OnKeyDispatch(HWND target, int key, int shift) {
    // Only unmodified configured keys in the mail-list window are accepted.
    if (shift != 0 || (key != g_ham_key && key != g_spam_key)) return 0;
    if (!g_becky_get_windows) {
        const auto becky_module = GetModuleHandleW(nullptr);
        g_becky_get_windows = becky_module
            ? reinterpret_cast<BeckyGetWindowHandlesFn>(
                GetProcAddress(becky_module, "BKA_GetWindowHandles"))
            : nullptr;
    }
    if (!g_becky_get_windows) return 0;

    HWND main_window = nullptr, tree_window = nullptr;
    HWND list_window = nullptr, view_window = nullptr;
    if (!g_becky_get_windows(&main_window, &tree_window, &list_window, &view_window) ||
        !list_window) return 0;

    HWND focus = GetFocus();
    const bool list_has_focus = focus &&
        (focus == list_window || IsChild(list_window, focus));
    if (!(target == list_window || list_has_focus)) return 0;

    train_selected_messages(key == g_spam_key, "keyboard");
    return 1; // Suppress Becky!'s subsequent command for this key.
}

int WINAPI BKC_OnOpenMail(LPCSTR) {
    return 0;
}

int WINAPI BKC_OnEveryMinute() {
    return 0;
}
}
