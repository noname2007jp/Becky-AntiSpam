#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>

#include <string>
#include <filesystem>
#include <cwctype>
#include "data_paths.hpp"

namespace {
constexpr int kLogId = 7101;
constexpr int kTestId = 7102;
constexpr int kSaveId = 7103;
constexpr int kCloseId = 7104;
constexpr int kFolderId = 7105;
constexpr int kMigrationId = 7108;
constexpr int kHamKeyId = 7109;
constexpr int kSpamKeyId = 7110;

HWND g_window = nullptr;
HWND g_log = nullptr;
HWND g_test = nullptr;
HWND g_ham_key = nullptr;
HWND g_spam_key = nullptr;
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
void toggle_test() {
    if (g_test) EnableWindow(g_test, SendMessageW(g_log, BM_GETCHECK, 0, 0) == BST_CHECKED);
}
void load() {
    SendMessageW(g_log, BM_SETCHECK,
        GetPrivateProfileIntW(L"logging", L"enabled", 1, g_ini.c_str()) ? BST_CHECKED : BST_UNCHECKED, 0);
    SendMessageW(g_test, BM_SETCHECK,
        GetPrivateProfileIntW(L"test_mode", L"enabled", 0, g_ini.c_str()) ? BST_CHECKED : BST_UNCHECKED, 0);
    toggle_test();
    wchar_t ham[8] = L"H", spam[8] = L"S";
    GetPrivateProfileStringW(L"review", L"ham_key", L"H", ham, 8, g_ini.c_str());
    GetPrivateProfileStringW(L"review", L"spam_key", L"S", spam, 8, g_ini.c_str());
    SetWindowTextW(g_ham_key, ham);
    SetWindowTextW(g_spam_key, spam);
}
bool save() {
    const wchar_t* a = SendMessageW(g_log, BM_GETCHECK, 0, 0) == BST_CHECKED ? L"1" : L"0";
    const wchar_t* b = SendMessageW(g_test, BM_GETCHECK, 0, 0) == BST_CHECKED ? L"1" : L"0";
    wchar_t ham[8]{}, spam[8]{};
    GetWindowTextW(g_ham_key, ham, 8);
    GetWindowTextW(g_spam_key, spam, 8);
    if (wcslen(ham) != 1 || wcslen(spam) != 1 ||
        towupper(ham[0]) < L'A' || towupper(ham[0]) > L'Z' ||
        towupper(spam[0]) < L'A' || towupper(spam[0]) > L'Z' ||
        towupper(ham[0]) == towupper(spam[0])) {
        MessageBoxW(g_window, L"正常・迷惑のキーは、重複しないアルファベット1文字（A～Z）を指定してください。",
                    L"入力内容の確認", MB_OK | MB_ICONWARNING);
        return false;
    }
    ham[0] = towupper(ham[0]); spam[0] = towupper(spam[0]);
    return WritePrivateProfileStringW(L"logging", L"enabled", a, g_ini.c_str()) &&
           WritePrivateProfileStringW(L"test_mode", L"enabled", b, g_ini.c_str()) &&
           WritePrivateProfileStringW(L"review", L"ham_key", ham, g_ini.c_str()) &&
           WritePrivateProfileStringW(L"review", L"spam_key", spam, g_ini.c_str());
}
void show_migration(HWND hwnd) {
    std::wstring message =
        L"Becky AntiSpam の設定と学習データは、次のフォルダーに保存されています。\n\n";
    message += g_dir;
    message +=
        L"\n\n【別のPCへの移行手順】\n"
        L"1. 移行元PCでBecky!を完全に終了します。\n"
        L"2. 上記の「BeckyAntiSpam」フォルダー全体をコピーします。\n"
        L"3. 移行先PCでBecky!を一度起動して終了し、データ保存先を作成します。\n"
        L"4. 移行先PCの設定画面で「フォルダーを開く」を押し、表示された場所にコピーしたフォルダーの中身を上書きコピーします。\n"
        L"5. Becky!を起動します。\n\n"
        L"【注意】\n"
        L"・コピーの前に、移行元・移行先のBecky!を必ず終了してください。\n"
        L"・移行先に既存データがある場合は、先に別の場所へバックアップしてください。\n"
        L"・移行元と移行先で保存先のパスが異なる場合があります。移行先では、そのPCの設定画面に表示された保存先を使用してください。\n"
        L"・メール本文やメールデータは、このフォルダーには保存していません。";
    MessageBoxW(hwnd, message.c_str(), L"Becky AntiSpam - データ移行方法",
                MB_OK | MB_ICONINFORMATION);
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
        control(hwnd, L"BUTTON", L"判定キー", BS_GROUPBOX, 16, 180, 452, 94);
        control(hwnd, L"STATIC", L"正常として確定：", 0, 30, 204, 125, 22);
        g_ham_key = control(hwnd, L"EDIT", L"H", WS_BORDER | ES_AUTOHSCROLL | WS_TABSTOP, 160, 201, 42, 24, kHamKeyId);
        control(hwnd, L"STATIC", L"迷惑として確定：", 0, 230, 204, 125, 22);
        g_spam_key = control(hwnd, L"EDIT", L"S", WS_BORDER | ES_AUTOHSCROLL | WS_TABSTOP, 360, 201, 42, 24, kSpamKeyId);
        control(hwnd, L"STATIC", L"アルファベット1文字。正常・迷惑で異なるキーを指定します。", 0, 30, 239, 420, 20);
        control(hwnd, L"BUTTON", L"データ保存先", BS_GROUPBOX, 16, 286, 452, 102);
        control(hwnd, L"STATIC", g_dir.c_str(), SS_LEFT | SS_PATHELLIPSIS,
            30, 308, 420, 20);
        control(hwnd, L"BUTTON", L"フォルダーを開く", BS_PUSHBUTTON | WS_TABSTOP,
            30, 338, 140, 26, kFolderId);
        control(hwnd, L"BUTTON", L"移行方法", BS_PUSHBUTTON | WS_TABSTOP,
            182, 338, 120, 26, kMigrationId);
        control(hwnd, L"STATIC", L"※ メールの移動・削除は行いません。",
            0, 18, 398, 450, 24);
        // Keep the action buttons clear of the client-area bottom edge.
        // Right-aligned with a 10px gap and approximately 12px bottom margin.
        control(hwnd, L"BUTTON", L"保存", BS_DEFPUSHBUTTON | WS_TABSTOP, 300, 432, 78, 28, kSaveId);
        control(hwnd, L"BUTTON", L"閉じる", BS_PUSHBUTTON | WS_TABSTOP, 388, 432, 78, 28, kCloseId);
        load();
        return 0;
    case WM_COMMAND:
        if (LOWORD(wp) == kLogId) { toggle_test(); return 0; }
        if (LOWORD(wp) == kFolderId) {
            ShellExecuteW(hwnd, L"open", g_dir.c_str(), nullptr, nullptr, SW_SHOWNORMAL); return 0;
        }
        if (LOWORD(wp) == kMigrationId) { show_migration(hwnd); return 0; }
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
        g_window = nullptr; g_log = nullptr; g_test = nullptr; g_ham_key = nullptr; g_spam_key = nullptr; return 0;
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
        500, 510, owner, nullptr, GetModuleHandleW(nullptr), nullptr);
    if (g_window) { ShowWindow(g_window, SW_SHOWNORMAL); UpdateWindow(g_window); }
}
} // namespace

int show_plugin_setup(HWND owner) {
    show_settings(owner, 0);
    return (g_window && IsWindow(g_window)) ? 1 : 0;
}
