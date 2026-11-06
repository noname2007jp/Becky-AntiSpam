#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>
#include <shellapi.h>
#include <objbase.h>

#include <string>
#include <filesystem>
#include <cwchar>
#include "data_paths.hpp"

bool export_plugin_data(const wchar_t* folder, std::wstring& error);
bool import_plugin_data(const wchar_t* folder, std::wstring& error);

namespace {
constexpr int kLogId = 7101;
constexpr int kTestId = 7102;
constexpr int kSaveId = 7103;
constexpr int kCloseId = 7104;
constexpr int kFolderId = 7105;
constexpr int kExportId = 7106;
constexpr int kImportId = 7107;

HWND g_window = nullptr;
HWND g_log = nullptr;
HWND g_test = nullptr;
std::wstring g_dir;
std::wstring g_ini;

void font(HWND h) {
    if (h) SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)), TRUE);
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
bool choose_folder(HWND owner, std::wstring& folder, const wchar_t* title) {
    BROWSEINFOW bi{};
    bi.hwndOwner = owner;
    bi.lpszTitle = title;
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    LPITEMIDLIST item = SHBrowseForFolderW(&bi);
    if (!item) return false;
    wchar_t path[MAX_PATH]{};
    const bool ok = SHGetPathFromIDListW(item, path) != FALSE;
    CoTaskMemFree(item);
    if (!ok) return false;
    folder = path;
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
void do_export(HWND hwnd) {
    std::wstring folder, error;
    if (!choose_folder(hwnd, folder, L"エクスポート先のフォルダーを選択してください")) return;
    if (!export_plugin_data(folder.c_str(), error)) {
        MessageBoxW(hwnd, error.c_str(), L"Becky AntiSpam - エクスポート失敗", MB_OK | MB_ICONERROR);
        return;
    }
    MessageBoxW(hwnd, L"設定と学習データをエクスポートしました。\nメール本文やログは含まれません。",
                L"Becky AntiSpam", MB_OK | MB_ICONINFORMATION);
}
void do_import(HWND hwnd) {
    if (MessageBoxW(hwnd,
        L"選択したバックアップの設定と学習データで、現在のデータを置き換えます。\n"
        L"処理前に現在のデータは一時退避されます。\n\n続行しますか？",
        L"Becky AntiSpam - インポート確認", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES) return;
    std::wstring folder, error;
    if (!choose_folder(hwnd, folder, L"インポート元のバックアップフォルダーを選択してください")) return;
    if (!import_plugin_data(folder.c_str(), error)) {
        MessageBoxW(hwnd, error.c_str(), L"Becky AntiSpam - インポート失敗", MB_OK | MB_ICONERROR);
        return;
    }
    load();
    MessageBoxW(hwnd, L"設定と学習データをインポートしました。",
                L"Becky AntiSpam", MB_OK | MB_ICONINFORMATION);
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
        control(hwnd, L"BUTTON", L"バックアップ／PC移行", BS_GROUPBOX, 16, 260, 452, 76);
        control(hwnd, L"STATIC", L"設定と学習データを保存・復元します（ログ・メール本文は対象外）。",
            0, 30, 280, 420, 20);
        control(hwnd, L"BUTTON", L"エクスポート", BS_PUSHBUTTON | WS_TABSTOP,
            30, 304, 130, 24, kExportId);
        control(hwnd, L"BUTTON", L"インポート", BS_PUSHBUTTON | WS_TABSTOP,
            172, 304, 130, 24, kImportId);
        control(hwnd, L"STATIC",
            L"※ メールの移動・削除は行いません。",
            0, 18, 345, 450, 24);
        control(hwnd, L"BUTTON", L"保存", BS_DEFPUSHBUTTON | WS_TABSTOP, 300, 380, 78, 28, kSaveId);
        control(hwnd, L"BUTTON", L"閉じる", BS_PUSHBUTTON | WS_TABSTOP, 388, 380, 78, 28, kCloseId);
        load();
        return 0;
    case WM_COMMAND:
        if (LOWORD(wp) == kLogId) { toggle_test(); return 0; }
        if (LOWORD(wp) == kFolderId) {
            ShellExecuteW(hwnd, L"open", g_dir.c_str(), nullptr, nullptr, SW_SHOWNORMAL); return 0;
        }
        if (LOWORD(wp) == kExportId) { do_export(hwnd); return 0; }
        if (LOWORD(wp) == kImportId) { do_import(hwnd); return 0; }
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
        wc.hInstance = GetModuleHandleW(nullptr); wc.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
        wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1); wc.lpszClassName = cls;
        if (!RegisterClassExW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return;
        registered = true;
    }
    g_window = CreateWindowExW(WS_EX_DLGMODALFRAME, cls, L"Becky AntiSpam - 設定",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT,
        500, 465, owner, nullptr, GetModuleHandleW(nullptr), nullptr);
    if (g_window) { ShowWindow(g_window, SW_SHOWNORMAL); UpdateWindow(g_window); }
}
} // namespace

int show_plugin_setup(HWND owner) {
    show_settings(owner, 0);
    return (g_window && IsWindow(g_window)) ? 1 : 0;
}
