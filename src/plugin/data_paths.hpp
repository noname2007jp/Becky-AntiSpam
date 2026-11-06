#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>

#include <filesystem>
#include <string>
#include <system_error>

namespace beckyas::plugin {

inline std::filesystem::path data_directory() {
    wchar_t exe_path[MAX_PATH]{};
    const DWORD length = GetModuleFileNameW(nullptr, exe_path, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) return {};
    const auto exe_dir = std::filesystem::path(exe_path).parent_path();
    return exe_dir / L"Plugins" / L"BeckyAntiSpam";
}

inline std::filesystem::path legacy_data_directory() {
    wchar_t appdata[MAX_PATH]{};
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_APPDATA | CSIDL_FLAG_CREATE,
                                nullptr, SHGFP_TYPE_CURRENT, appdata))) return {};
    return std::filesystem::path(appdata) / L"BeckyAntiSpam";
}

// Copy only files that do not already exist at the portable destination.
// SQLite sidecar files are included so a database with pending WAL data is preserved.
inline bool prepare_data_directory(std::filesystem::path& destination,
                                   std::wstring* error = nullptr) {
    destination = data_directory();
    if (destination.empty()) {
        if (error) *error = L"Becky! のインストール先を特定できません。";
        return false;
    }

    std::error_code ec;
    std::filesystem::create_directories(destination, ec);
    if (ec) {
        if (error) *error = L"Plugins\\BeckyAntiSpam を作成できません。書き込み権限を確認してください。";
        return false;
    }

    const auto legacy = legacy_data_directory();
    if (!legacy.empty() && legacy != destination &&
        std::filesystem::exists(legacy, ec) && !ec) {
        static const wchar_t* files[] = {
            L"settings.ini", L"training.sqlite3", L"training.sqlite3-wal",
            L"training.sqlite3-shm", L"operation.log", L"operation.log.1",
            L"test-detail.log", L"test-detail.log.1"
        };
        for (const auto* name : files) {
            ec.clear();
            const auto from = legacy / name;
            const auto to = destination / name;
            if (!std::filesystem::exists(to, ec) && !ec &&
                std::filesystem::exists(from, ec) && !ec) {
                ec.clear();
                std::filesystem::copy_file(from, to,
                    std::filesystem::copy_options::none, ec);
                if (ec && error) {
                    *error = L"旧保存先からの移行に失敗しました。旧データは削除していません。";
                    return false;
                }
            }
        }
    }

    // Verify write access before the plugin starts using the folder.
    const auto probe = destination / L".write-test";
    HANDLE h = CreateFileW(probe.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        if (error) *error = L"保存先に書き込めません。フォルダーのアクセス権を確認してください。";
        return false;
    }
    CloseHandle(h);
    return true;
}

} // namespace beckyas::plugin
