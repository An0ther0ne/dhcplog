// dhcplog.cpp : Defines the entry point for the application.
//

#include "framework.h"
#include "dhcplog.h"
#include <thread>
#include <memory>
#include "logger.h"
#include "sniffer.h"

#define MAX_LOADSTRING 100

// Global Variables:
HINSTANCE hInst;                                // current instance
WCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
WCHAR szWindowClass[MAX_LOADSTRING];            // the main window class name
HWND g_hEdit = nullptr;
std::unique_ptr<LogManager> g_logger;
std::unique_ptr<DhcpSniffer> g_sniffer;
bool g_captureStarted = false;

// Forward declarations of functions included in this code module:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // TODO: Place code here.

    // Initialize global strings
    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_DHCPLOG, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    // Perform application initialization:
    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_DHCPLOG));

    MSG msg;

    // Main message loop:
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int) msg.wParam;
}



//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_DHCPLOG));
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = MAKEINTRESOURCEW(IDC_DHCPLOG);
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassExW(&wcex);
}

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   hInst = hInstance; // Store instance handle in our global variable

   HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, nullptr, nullptr, hInstance, nullptr);

   if (!hWnd)
   {
      return FALSE;
   }

   // create a multiline read-only edit control to show log lines
   g_hEdit = CreateWindowEx(0, L"EDIT", NULL,
       WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_LEFT | ES_READONLY | ES_AUTOVSCROLL | ES_MULTILINE,
       0, 0, 800, 600, hWnd, (HMENU)1000, hInstance, NULL);

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   // initialize logger and sniffer
   g_logger = std::make_unique<LogManager>(L"logs", LogManager::Rotation::Daily, hWnd);
   g_logger->Start();
   g_sniffer = std::make_unique<DhcpSniffer>(hWnd, g_logger.get());
   // start capture automatically
   g_sniffer->Start();
   g_captureStarted = true;

   return TRUE;
}

//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE: Processes messages for the main window.
//
//  WM_COMMAND  - process the application menu
//  WM_PAINT    - Paint the main window
//  WM_DESTROY  - post a quit message and return
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_COMMAND:
        {
            int wmId = LOWORD(wParam);
            // Parse the menu selections:
            switch (wmId)
            {
            case IDM_TOGGLE_CAPTURE:
                if (g_sniffer)
                {
                    if (g_captureStarted) { g_sniffer->Stop(); g_captureStarted = false; g_logger->Log("INFO: Capture stopped by user"); }
                    else { g_sniffer->Start(); g_captureStarted = true; g_logger->Log("INFO: Capture started by user"); }
                }
                break;
            case IDM_ROTATION_DAILY:
                if (g_logger) { g_logger->SetRotation(LogManager::Rotation::Daily); g_logger->Log("INFO: Rotation set to daily"); }
                break;
            case IDM_ROTATION_WEEKLY:
                if (g_logger) { g_logger->SetRotation(LogManager::Rotation::Weekly); g_logger->Log("INFO: Rotation set to weekly"); }
                break;
            case IDM_ABOUT:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
                break;
            case IDM_EXIT:
                DestroyWindow(hWnd);
                break;
            default:
                return DefWindowProc(hWnd, message, wParam, lParam);
            }
        }
        break;
    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            BeginPaint(hWnd, &ps);
            // TODO: Add any drawing code here...
            EndPaint(hWnd, &ps);
        }
        break;
    case WM_DESTROY:
        // stop sniffer and logger
        if (g_sniffer) { g_sniffer->Stop(); }
        if (g_logger) { g_logger->Stop(); }
        PostQuitMessage(0);
        break;
    case WM_SIZE:
        {
            if (g_hEdit) {
                RECT rc;
                GetClientRect(hWnd, &rc);
                SetWindowPos(g_hEdit, NULL, 0, 0, rc.right - rc.left, rc.bottom - rc.top, SWP_NOZORDER);
            }
        }
        break;
    case WM_APP+1:
        {
            // lParam is a pointer to std::string allocated by caller
            std::string* p = (std::string*)lParam;
            if (p && g_hEdit) {
                std::string s = *p;
                // append to edit control
                int len = (int)MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, NULL, 0);
                std::wstring w;
                w.resize(len);
                MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], len);
                // remove the extra null char
                if (!w.empty() && w.back() == L'\0') w.pop_back();
                // append and add newline
                int start = GetWindowTextLengthW(g_hEdit);
                SendMessageW(g_hEdit, EM_SETSEL, (WPARAM)start, (LPARAM)start);
                std::wstring out = w + L"\r\n";
                SendMessageW(g_hEdit, EM_REPLACESEL, FALSE, (LPARAM)out.c_str());
            }
            delete p;
        }
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// Message handler for about box.
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}
