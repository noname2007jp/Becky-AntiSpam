#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>
#include <shellapi.h>

#include <string>
#include <filesystem>
#include <cwchar>
#include "data_paths.hpp"

namespace {
using RegisterCommandFn = UINT (WINAPI*)(LPCSTR, int, void (CALLBACK*)(HWND, LPARAM));
constexpr int kMenuMain = 0;
constexpr int kLogId = 7101;
constexpr int kTestId = 7102;
constexpr int kSaveId = 7103;
constexpr int kCloseId = 7104;
constexpr int kFolderId = 7105;

HWND g_window = nullptr;
HWND g_log = nullptr;
HWND g_test = nullptr;
std::wstring g_dir;
std::wstring g_ini;

void font(HWND h) {
    SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)), TRUE);
}
HWND control(HWND parent, const wchar_t* cls, const wchar_t* text, DWORD style,
             int x, int y, int w, int h, int id = 0) {
    HWND v = CreateWindowExW(0, cls, text, WS_CHILD | WS_VISIBLE | style,
        x, y, w, h, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
        GetModuleHandleW(nullptr), nullptr);
    font(v);
    return v;
}
bool paths() {
    std::filesystem::path directory;
    std::wstring error;
    if (!beckyas::plugin::prepare_data_directory(directory, &error)) {
        MessageBoxW(nullptr, error.c_str(), L"Becky AntiSpam", MB_OK | MB_ICONERROR);
        return false;
    }
    g_dir = directory.wstring();
    g_ini = g_dir + L"\\settings.ini";
    return true;
}

void toggle_test() {
    if (g_test) EnableWindow(g_test, SendMessageW(g_log, BM_GETCHECK, 0, 0) == BST_CHECKED);
}
void load() {
    SendMessageW(g_log, BM_SETCHECK,
        GetPrivateProfileIntW(L"logging", L"enabled", 1, g_ini.c_str()) ? BST_CHECKED : BST_UNCHECKED, 0);
    SendMessageW(g_test, BM_SETCHECK,
        GetPrivateProfileIntW(L"test_mode", L"enabled", 0, g_ini.c_str()) ? BST_CHECKED : BST_UNCHECKED, 0);
    toggle_test();
}
bool save() {
    const wchar_t* a = SendMessageW(g_log, BM_GETCHECK, 0, 0) == BST_CHECKED ? L"1" : L"0";
    const wchar_t* b = SendMessageW(g_test, BM_GETCHECK, 0, 0) == BST_CHECKED ? L"1" : L"0";
    return WritePrivateProfileStringW(L"logging", L"enabled", a, g_ini.c_str()) &&
           WritePrivateProfileStringW(L"test_mode", L"enabled", b, g_ini.c_str());
}
LRESULT CALLBACK dialog_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE:
        control(hwnd, L"STATIC", L"Becky AntiSpam の動作設定", 0, 18, 14, 430, 24);
        control(hwnd, L"BUTTON", L"ログ出力", BS_GROUPBOX, 16, 44, 452, 125);
        g_log = control(hwnd, L"BUTTON", L"通常ログを出力する（operation.log）",
            BS_AUTOCHECKBOX | WS_TABSTOP, 32, 70, 420, 24, kLogId);
        g_test = control(hwnd, L"BUTTON", L"詳細テストログを出力する（test-detail.log）",
            BS_AUTOCHECKBOX | WS_TABSTOP, 32, 101, 420, 24, kTestId);
        control(hwnd, L"STATIC", L"詳細ログには解析結果・判定ルール・警告が記録されます。通常運用ではOFFを推奨します。",
            0, 32, 132, 420, 30);
        control(hwnd, L"BUTTON", L"データ保存先", BS_GROUPBOX, 16, 180, 452, 72);
        control(hwnd, L"STATIC", g_dir.c_str(), 0, 30, 202, 420, 20);
        control(hwnd, L"BUTTON", L"フォルダーを開く", BS_PUSHBUTTON | WS_TABSTOP,
            30, 225, 140, 24, kFolderId);
        control(hwnd, L"STATIC",
            L"※ 現在変更できるのはログ設定です。メールの移動・削除は行いません。",
            0, 18, 270, 450, 28);
        control(hwnd, L"BUTTON", L"保存", BS_DEFPUSHBUTTON | WS_TABSTOP, 300, 315, 78, 28, kSaveId);
        control(hwnd, L"BUTTON", L"閉じる", BS_PUSHBUTTON | WS_TABSTOP, 388, 315, 78, 28, kCloseId);
        load();
        return 0;
    case WM_COMMAND:
        if (LOWORD(wp) == kLogId) { toggle_test(); return 0; }
        if (LOWORD(wp) == kFolderId) {
            ShellExecuteW(hwnd, L"open", g_dir.c_str(), nullptr, nullptr, SW_SHOWNORMAL); return 0;
        }
        if (LOWORD(wp) == kSaveId) {
            if (save()) MessageBoxW(hwnd, L"設定を保存しました。\nBecky! を再起動すると反映されます。",
                                    L"Becky AntiSpam", MB_OK | MB_ICONINFORMATION);
            else MessageBoxW(hwnd, L"設定ファイルを保存できませんでした。",
                             L"Becky AntiSpam", MB_OK | MB_ICONERROR);
            return 0;
        }
        if (LOWORD(wp) == kCloseId) { DestroyWindow(hwnd); return 0; }
        break;
    case WM_CLOSE: DestroyWindow(hwnd); return 0;
    case WM_DESTROY:
        g_window = nullptr; g_log = nullptr; g_test = nullptr; return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}
void CALLBACK show_settings(HWND owner, LPARAM) {
    if (g_window && IsWindow(g_window)) {
        ShowWindow(g_window, SW_SHOWNORMAL); SetForegroundWindow(g_window); return;
    }
    if (!paths()) {
        MessageBoxW(owner, L"設定フォルダーを準備できませんでした。",
                    L"Becky AntiSpam", MB_OK | MB_ICONERROR); return;
    }
    const wchar_t cls[] = L"BeckyAntiSpamSettingsDialog";
    static bool registered = false;
    if (!registered) {
        WNDCLASSEXW wc{}; wc.cbSize = sizeof(wc); wc.lpfnWndProc = dialog_proc;
        wc.hInstance = GetModuleHandleW(nullptr); wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1); wc.lpszClassName = cls;
        if (!RegisterClassExW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return;
        registered = true;
    }
    g_window = CreateWindowExW(WS_EX_DLGMODALFRAME, cls, L"Becky AntiSpam - 設定",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT,
        500, 400, owner, nullptr, GetModuleHandleW(nullptr), nullptr);
    if (g_window) { ShowWindow(g_window, SW_SHOWNORMAL); UpdateWindow(g_window); }
}
bool contains_plugin_settings(HMENU menu) {
    const int count = GetMenuItemCount(menu);
    for (int i = 0; i < count; ++i) {
        wchar_t label[256]{};
        GetMenuStringW(menu, i, label, 256, MF_BYPOSITION);
        if (wcsstr(label, L"プラグインの設定")) return true;
    }
    return false;
}
HMENU find_plugin_settings_menu(HMENU menu) {
    const int count = GetMenuItemCount(menu);
    for (int i = 0; i < count; ++i) {
        wchar_t label[256]{};
        GetMenuStringW(menu, i, label, 256, MF_BYPOSITION);
        HMENU sub = GetSubMenu(menu, i);
        if (sub && wcsstr(label, L"プラグインの設定")) return sub;
        if (sub) if (HMENU found = find_plugin_settings_menu(sub)) return found;
    }
    return nullptr;
}
} // namespace

void initialize_settings_menu(HWND, HMENU menu, int type) {
    if (type != kMenuMain || !menu || !paths()) return;
    static UINT command_id = 0;
    if (command_id) return;
    HMODULE exe = GetModuleHandleW(nullptr);
    auto reg = reinterpret_cast<RegisterCommandFn>(GetProcAddress(exe, "BKA_RegisterCommand"));
    if (!reg) return;
    command_id = reg("Open Becky AntiSpam settings", type, show_settings);
    if (!command_id) return;
    HMENU target = find_plugin_settings_menu(menu);
    if (target) AppendMenuW(target, MF_STRING, command_id, L"Becky AntiSpam");
}
