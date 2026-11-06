#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>
#include <shellapi.h>

#include <string>

namespace {
constexpr int ID_LOGGING = 1001;
constexpr int ID_TEST_MODE = 1002;
constexpr int ID_OPEN_FOLDER = 1003;
constexpr int ID_SAVE = 1004;
constexpr int ID_CANCEL = 1005;

HWND g_logging = nullptr;
HWND g_test_mode = nullptr;
HWND g_status = nullptr;
std::wstring g_data_dir;
std::wstring g_ini_path;

void set_font(HWND control) {
    SendMessageW(control, WM_SETFONT,
        reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)), TRUE);
}

HWND add_control(HWND parent, const wchar_t* klass, const wchar_t* text,
                 DWORD style, int x, int y, int width, int height, int id = 0) {
    HWND control = CreateWindowExW(0, klass, text, WS_CHILD | WS_VISIBLE | style,
        x, y, width, height, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
        GetModuleHandleW(nullptr), nullptr);
    set_font(control);
    return control;
}

void update_test_enabled() {
    EnableWindow(g_test_mode, SendMessageW(g_logging, BM_GETCHECK, 0, 0) == BST_CHECKED);
}

bool initialize_paths() {
    wchar_t appdata[MAX_PATH] = {};
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_APPDATA | CSIDL_FLAG_CREATE,
                                nullptr, SHGFP_TYPE_CURRENT, appdata))) return false;
    g_data_dir = appdata;
    g_data_dir += L"\\BeckyAntiSpam";
    if (!CreateDirectoryW(g_data_dir.c_str(), nullptr) &&
        GetLastError() != ERROR_ALREADY_EXISTS) return false;
    g_ini_path = g_data_dir + L"\\settings.ini";
    return true;
}

void load_settings() {
    const bool logging = GetPrivateProfileIntW(L"logging", L"enabled", 1,
        g_ini_path.c_str()) != 0;
    const bool test = GetPrivateProfileIntW(L"test_mode", L"enabled", 0,
        g_ini_path.c_str()) != 0;
    SendMessageW(g_logging, BM_SETCHECK, logging ? BST_CHECKED : BST_UNCHECKED, 0);
    SendMessageW(g_test_mode, BM_SETCHECK, test ? BST_CHECKED : BST_UNCHECKED, 0);
    update_test_enabled();
}

bool save_settings() {
    const wchar_t* logging = SendMessageW(g_logging, BM_GETCHECK, 0, 0) == BST_CHECKED ? L"1" : L"0";
    const wchar_t* test = SendMessageW(g_test_mode, BM_GETCHECK, 0, 0) == BST_CHECKED ? L"1" : L"0";
    if (!WritePrivateProfileStringW(L"logging", L"enabled", logging, g_ini_path.c_str()) ||
        !WritePrivateProfileStringW(L"test_mode", L"enabled", test, g_ini_path.c_str())) {
        MessageBoxW(nullptr, L"設定ファイルを保存できませんでした。", L"Becky AntiSpam",
                    MB_OK | MB_ICONERROR);
        return false;
    }
    return true;
}

LRESULT CALLBACK window_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
    switch (message) {
    case WM_CREATE: {
        add_control(hwnd, L"STATIC", L"Becky AntiSpam の動作設定を変更します。",
                    0, 18, 14, 440, 22);
        add_control(hwnd, L"BUTTON", L"ログ設定", BS_GROUPBOX,
                    16, 45, 452, 130);
        g_logging = add_control(hwnd, L"BUTTON", L"通常ログを出力する（operation.log）",
                    BS_AUTOCHECKBOX | WS_TABSTOP, 32, 72, 410, 24, ID_LOGGING);
        g_test_mode = add_control(hwnd, L"BUTTON", L"詳細テストログを出力する（test-detail.log）",
                    BS_AUTOCHECKBOX | WS_TABSTOP, 32, 103, 420, 24, ID_TEST_MODE);
        add_control(hwnd, L"STATIC",
            L"詳細ログには判定ルールや解析警告が記録されます。通常運用ではOFFを推奨します。",
            0, 32, 135, 420, 30);

        add_control(hwnd, L"BUTTON", L"保存先", BS_GROUPBOX,
                    16, 184, 452, 76);
        add_control(hwnd, L"STATIC", g_data_dir.c_str(),
                    0, 30, 207, 420, 22);
        add_control(hwnd, L"BUTTON", L"保存フォルダーを開く",
                    BS_PUSHBUTTON | WS_TABSTOP, 30, 232, 160, 25, ID_OPEN_FOLDER);

        add_control(hwnd, L"BUTTON", L"今後追加予定の機能", BS_GROUPBOX,
                    16, 270, 452, 105);
        add_control(hwnd, L"STATIC",
            L"・判定しきい値／ルール設定　・学習データ管理　・安心／迷惑リスト\n"
            L"・自動振り分け（初期状態OFF）　・AI連携（初期状態OFF）",
            0, 30, 294, 425, 52);
        add_control(hwnd, L"STATIC",
            L"※ 現在この画面で変更できるのはログ設定です。メールの移動・削除は行いません。",
            0, 18, 386, 450, 28);

        add_control(hwnd, L"BUTTON", L"保存", BS_DEFPUSHBUTTON | WS_TABSTOP,
                    294, 430, 78, 28, ID_SAVE);
        add_control(hwnd, L"BUTTON", L"閉じる", BS_PUSHBUTTON | WS_TABSTOP,
                    382, 430, 78, 28, ID_CANCEL);
        load_settings();
        return 0;
    }
    case WM_COMMAND:
        switch (LOWORD(wparam)) {
        case ID_LOGGING:
            update_test_enabled();
            return 0;
        case ID_OPEN_FOLDER:
            ShellExecuteW(hwnd, L"open", g_data_dir.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            return 0;
        case ID_SAVE:
            if (save_settings()) {
                SetWindowTextW(g_status, L"");
                MessageBoxW(hwnd,
                    L"設定を保存しました。\nBecky! を再起動すると設定が反映されます。",
                    L"Becky AntiSpam", MB_OK | MB_ICONINFORMATION);
            }
            return 0;
        case ID_CANCEL:
            DestroyWindow(hwnd);
            return 0;
        }
        break;
    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, message, wparam, lparam);
}
} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show) {
    if (!initialize_paths()) {
        MessageBoxW(nullptr, L"%APPDATA%\\BeckyAntiSpam を準備できませんでした。",
                    L"Becky AntiSpam", MB_OK | MB_ICONERROR);
        return 1;
    }

    const wchar_t class_name[] = L"BeckyAntiSpamSettingsWindow";
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = window_proc;
    wc.hInstance = instance;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
    wc.lpszClassName = class_name;
    if (!RegisterClassExW(&wc)) return 1;

    HWND hwnd = CreateWindowExW(WS_EX_DLGMODALFRAME, class_name,
        L"Becky AntiSpam - 設定", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU |
        WS_MINIMIZEBOX, CW_USEDEFAULT, CW_USEDEFAULT, 500, 510,
        nullptr, nullptr, instance, nullptr);
    if (!hwnd) return 1;
    ShowWindow(hwnd, show);
    UpdateWindow(hwnd);

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return static_cast<int>(msg.wParam);
}
