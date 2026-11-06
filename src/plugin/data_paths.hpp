#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>

#include <filesystem>
#include <string>
#include <system_error>

namespace beckyas::plugin {

inline std::filesystem::path preferred_data_directory() {
    wchar_t exe_path[MAX_PATH]{};
    const DWORD length = GetModuleFileNameW(nullptr, exe_path, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) return {};
    return std::filesystem::path(exe_path).parent_path() /
        L"Plugins" / L"BeckyAntiSpam";
}

inline std::filesystem::path legacy_data_directory() {
    wchar_t appdata[MAX_PATH]{};
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_APPDATA | CSIDL_FLAG_CREATE,
                                nullptr, SHGFP_TYPE_CURRENT, appdata))) return {};
    return std::filesystem::path(appdata) / L"BeckyAntiSpam";
}

inline bool ensure_writable_directory(const std::filesystem::path& directory) {
    if (directory.empty()) return false;
    std::error_code ec;
    std::filesystem::create_directories(directory, ec);
    if (ec) return false;

    const auto probe = directory / L".write-test";
    HANDLE h = CreateFileW(probe.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    CloseHandle(h);
    return true;
}

// Prefer a portable folder beside Becky!. If that location is protected (for
// example, Program Files), fall back to the per-user AppData folder. This
// avoids requiring elevation and keeps the active path available to the UI.
inline bool prepare_data_directory(std::filesystem::path& destination,
                                   std::wstring* error = nullptr) {
    const auto portable = preferred_data_directory();
    if (!portable.empty() && ensure_writable_directory(portable)) {
        destination = portable;

        // Migrate legacy files only after confirming the portable destination
        // is writable. Never overwrite an existing destination file.
        const auto legacy = legacy_data_directory();
        if (!legacy.empty() && legacy != destination) {
            static const wchar_t* files[] = {
                L"settings.ini", L"training.sqlite3", L"training.sqlite3-wal",
                L"training.sqlite3-shm", L"operation.log", L"operation.log.1",
                L"test-detail.log", L"test-detail.log.1"
            };
            std::error_code ec;
            if (std::filesystem::exists(legacy, ec) && !ec) {
                for (const auto* name : files) {
                    ec.clear();
                    const auto from = legacy / name;
                    const auto to = destination / name;
                    if (!std::filesystem::exists(to, ec) && !ec &&
                        std::filesystem::exists(from, ec) && !ec) {
                        ec.clear();
                        std::filesystem::copy_file(from, to,
                            std::filesystem::copy_options::none, ec);
                        if (ec) {
                            if (error) *error = L"旧保存先からの移行に失敗しました。旧データは削除していません。";
                            return false;
                        }
                    }
                }
            }
        }
        return true;
    }

    // Protected install directories cannot be used for per-user writable data.
    // Use the existing AppData location as a safe fallback without elevation.
    const auto fallback = legacy_data_directory();
    if (!fallback.empty() && ensure_writable_directory(fallback)) {
        destination = fallback;
        return true;
    }

    if (error) {
        *error = L"保存先を作成できません。\nBecky!のPluginsフォルダーにもユーザーのAppDataにも書き込めません。";
    }
    return false;
}

} // namespace beckyas::plugin
