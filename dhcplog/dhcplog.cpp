// dhcplog.cpp : Defines the entry point for the application.
//

#include "framework.h"
#include "dhcplog.h"

#include <thread>
#include <memory>
#include <string>
#include <vector>
#include <algorithm>

#include <winsock2.h>
#include <iphlpapi.h>

#pragma comment(lib, "Iphlpapi.lib")

#include "logger.h"
#include "sniffer.h"

#define MAX_LOADSTRING 100

// Global Variables:
HINSTANCE hInst;
WCHAR szTitle[MAX_LOADSTRING];
WCHAR szWindowClass[MAX_LOADSTRING];

HWND g_hEdit = nullptr;
HWND g_hInterfaceCombo = nullptr;

std::unique_ptr<LogManager> g_logger;
std::unique_ptr<DhcpSniffer> g_sniffer;

bool g_captureStarted = false;

static constexpr int ID_INTERFACE_COMBO = 1001;
static constexpr int ID_START_CAPTURE = 1002;

struct NetworkAdapter
{
    std::wstring friendlyName;
    std::wstring adapterName;
};

// Forward declarations
ATOM MyRegisterClass(HINSTANCE hInstance);

BOOL InitInstance(HINSTANCE, int);

LRESULT CALLBACK WndProc(
    HWND,
    UINT,
    WPARAM,
    LPARAM);

INT_PTR CALLBACK About(
    HWND,
    UINT,
    WPARAM,
    LPARAM);

static std::vector<NetworkAdapter> GetNetworkAdapters();

static std::string WideToUtf8(
    const std::wstring& value);

static std::string AdapterNameToPcapDevice(
    const std::wstring& adapterName);

static bool StartCapture(HWND hWnd);


// ------------------------------------------------------------
// Get Windows network adapters.
// ------------------------------------------------------------

static std::vector<NetworkAdapter> GetNetworkAdapters()
{
    std::vector<NetworkAdapter> result;

    ULONG bufferSize = 15 * 1024;

    std::vector<unsigned char> buffer(bufferSize);

    IP_ADAPTER_ADDRESSES* adapters =
        reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());

    ULONG flags =
        GAA_FLAG_SKIP_ANYCAST |
        GAA_FLAG_SKIP_MULTICAST |
        GAA_FLAG_SKIP_DNS_SERVER;

    ULONG ret = GetAdaptersAddresses(
        AF_UNSPEC,
        flags,
        nullptr,
        adapters,
        &bufferSize);

    if (ret == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(bufferSize);

        adapters =
            reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());

        ret = GetAdaptersAddresses(
            AF_UNSPEC,
            flags,
            nullptr,
            adapters,
            &bufferSize);
    }

    if (ret != NO_ERROR)
        return result;

    for (IP_ADAPTER_ADDRESSES* adapter = adapters;
        adapter != nullptr;
        adapter = adapter->Next) {

        if (!adapter->AdapterName)
            continue;

        if (!adapter->FriendlyName)
            continue;

        if (adapter->OperStatus != IfOperStatusUp)
            continue;

        if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
            continue;

        NetworkAdapter item;

        item.friendlyName = adapter->FriendlyName;

        // AdapterName is normally the adapter GUID
        // without the "\Device\NPF_" prefix.
        item.adapterName =
            std::wstring(
                adapter->AdapterName,
                adapter->AdapterName +
                strlen(adapter->AdapterName));

        result.push_back(std::move(item));
    }

    return result;
}


// ------------------------------------------------------------
// UTF-16 -> UTF-8
// ------------------------------------------------------------

static std::string WideToUtf8(
    const std::wstring& value)
{
    if (value.empty())
        return {};

    int size = WideCharToMultiByte(
        CP_UTF8,
        0,
        value.c_str(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr);

    if (size <= 0)
        return {};

    std::string result(size, '\0');

    WideCharToMultiByte(
        CP_UTF8,
        0,
        value.c_str(),
        static_cast<int>(value.size()),
        result.data(),
        size,
        nullptr,
        nullptr);

    return result;
}


// ------------------------------------------------------------
// Windows AdapterName -> Npcap device name
// ------------------------------------------------------------

static std::string AdapterNameToPcapDevice(
    const std::wstring& adapterName)
{
    std::string guid = WideToUtf8(adapterName);

    return "\\Device\\NPF_{" + guid + "}";
}


// ------------------------------------------------------------
// Start capture for selected interface
// ------------------------------------------------------------

static bool StartCapture(HWND hWnd)
{
    if (g_sniffer)
        return false;

    if (!g_hInterfaceCombo)
        return false;

    int index = static_cast<int>(
        SendMessage(
            g_hInterfaceCombo,
            CB_GETCURSEL,
            0,
            0));

    if (index == CB_ERR)
        return false;

    auto* adapter =
        reinterpret_cast<NetworkAdapter*>(
            SendMessage(
                g_hInterfaceCombo,
                CB_GETITEMDATA,
                index,
                0));

    if (!adapter)
        return false;

    std::string pcapDevice =
        AdapterNameToPcapDevice(adapter->adapterName);

    g_logger = std::make_unique<LogManager>(
        L"logs",
        LogManager::Rotation::Daily,
        hWnd);

    g_logger->Start();

    g_sniffer =
        std::make_unique<DhcpSniffer>(
            hWnd,
            g_logger.get(),
            pcapDevice);

    g_sniffer->Start();

    g_captureStarted = true;

    g_logger->Log(
        "INFO: capture started");

    return true;
}


// ------------------------------------------------------------
// Application entry point
// ------------------------------------------------------------

int APIENTRY wWinMain(
    _In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPWSTR lpCmdLine,
    _In_ int nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    LoadStringW(
        hInstance,
        IDS_APP_TITLE,
        szTitle,
        MAX_LOADSTRING);

    LoadStringW(
        hInstance,
        IDC_DHCPLOG,
        szWindowClass,
        MAX_LOADSTRING);

    MyRegisterClass(hInstance);

    if (!InitInstance(hInstance, nCmdShow))
        return FALSE;

    HACCEL hAccelTable =
        LoadAccelerators(
            hInstance,
            MAKEINTRESOURCE(IDC_DHCPLOG));

    MSG msg;

    while (GetMessage(&msg, nullptr, 0, 0)) {

        if (!TranslateAccelerator(
            msg.hwnd,
            hAccelTable,
            &msg)) {

            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return static_cast<int>(msg.wParam);
}


// ------------------------------------------------------------
// Register window class
// ------------------------------------------------------------

ATOM MyRegisterClass(
    HINSTANCE hInstance)
{
    WNDCLASSEXW wcex{};

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style =
        CS_HREDRAW |
        CS_VREDRAW;

    wcex.lpfnWndProc = WndProc;

    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;

    wcex.hInstance = hInstance;

    wcex.hIcon =
        LoadIcon(
            hInstance,
            MAKEINTRESOURCE(IDI_DHCPLOG));

    wcex.hCursor =
        LoadCursor(
            nullptr,
            IDC_ARROW);

    wcex.hbrBackground =
        reinterpret_cast<HBRUSH>(
            COLOR_WINDOW + 1);

    wcex.lpszMenuName =
        MAKEINTRESOURCEW(IDC_DHCPLOG);

    wcex.lpszClassName =
        szWindowClass;

    wcex.hIconSm =
        LoadIcon(
            wcex.hInstance,
            MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassExW(&wcex);
}


// ------------------------------------------------------------
// Initialize main window
// ------------------------------------------------------------

BOOL InitInstance(
    HINSTANCE hInstance,
    int nCmdShow)
{
    hInst = hInstance;

    HWND hWnd =
        CreateWindowW(
            szWindowClass,
            szTitle,
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            0,
            900,
            650,
            nullptr,
            nullptr,
            hInstance,
            nullptr);

    if (!hWnd)
        return FALSE;


    // Interface label

    CreateWindowW(
        L"STATIC",
        L"Network interface:",
        WS_CHILD | WS_VISIBLE,
        10,
        10,
        130,
        24,
        hWnd,
        nullptr,
        hInstance,
        nullptr);


    // Interface ComboBox

    g_hInterfaceCombo =
        CreateWindowW(
            L"COMBOBOX",
            nullptr,
            WS_CHILD |
            WS_VISIBLE |
            WS_VSCROLL |
            CBS_DROPDOWNLIST,
            145,
            7,
            450,
            300,
            hWnd,
            reinterpret_cast<HMENU>(
                ID_INTERFACE_COMBO),
            hInstance,
            nullptr);


    // Start button

    CreateWindowW(
        L"BUTTON",
        L"Start capture",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        610,
        7,
        120,
        28,
        hWnd,
        reinterpret_cast<HMENU>(
            ID_START_CAPTURE),
        hInstance,
        nullptr);


    // Log window

    g_hEdit =
        CreateWindowEx(
            0,
            L"EDIT",
            nullptr,
            WS_CHILD |
            WS_VISIBLE |
            WS_VSCROLL |
            ES_LEFT |
            ES_READONLY |
            ES_AUTOVSCROLL |
            ES_MULTILINE,
            0,
            45,
            800,
            550,
            hWnd,
            reinterpret_cast<HMENU>(1000),
            hInstance,
            nullptr);


    // Enumerate Windows adapters

    std::vector<NetworkAdapter> adapters =
        GetNetworkAdapters();

    for (auto& adapter : adapters) {

        int index =
            static_cast<int>(
                SendMessageW(
                    g_hInterfaceCombo,
                    CB_ADDSTRING,
                    0,
                    reinterpret_cast<LPARAM>(
                        adapter.friendlyName.c_str())));

        if (index == CB_ERR)
            continue;

        auto* stored =
            new NetworkAdapter(
                std::move(adapter));

        SendMessage(
            g_hInterfaceCombo,
            CB_SETITEMDATA,
            index,
            reinterpret_cast<LPARAM>(stored));
    }

    if (SendMessage(
        g_hInterfaceCombo,
        CB_GETCOUNT,
        0,
        0) > 0) {

        SendMessage(
            g_hInterfaceCombo,
            CB_SETCURSEL,
            0,
            0);
    }


    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    return TRUE;
}


// ------------------------------------------------------------
// Window procedure
// ------------------------------------------------------------

LRESULT CALLBACK WndProc(
    HWND hWnd,
    UINT message,
    WPARAM wParam,
    LPARAM lParam)
{
    switch (message)
    {
    case WM_COMMAND:
    {
        int wmId = LOWORD(wParam);

        switch (wmId)
        {
        case ID_START_CAPTURE:

            if (!g_captureStarted) {

                if (!StartCapture(hWnd)) {

                    MessageBoxW(
                        hWnd,
                        L"Failed to start capture.",
                        L"DHCP Logger",
                        MB_ICONERROR);
                }
            }

            break;


        case IDM_TOGGLE_CAPTURE:

            if (g_sniffer) {

                if (g_captureStarted) {

                    g_sniffer->Stop();

                    g_captureStarted = false;

                    if (g_logger)
                        g_logger->Log(
                            "INFO: Capture stopped by user");
                }
                else {

                    g_sniffer->Start();

                    g_captureStarted = true;

                    if (g_logger)
                        g_logger->Log(
                            "INFO: Capture started by user");
                }
            }

            break;


        case IDM_ROTATION_DAILY:

            if (g_logger) {

                g_logger->SetRotation(
                    LogManager::Rotation::Daily);

                g_logger->Log(
                    "INFO: Rotation set to daily");
            }

            break;


        case IDM_ROTATION_WEEKLY:

            if (g_logger) {

                g_logger->SetRotation(
                    LogManager::Rotation::Weekly);

                g_logger->Log(
                    "INFO: Rotation set to weekly");
            }

            break;


        case IDM_ABOUT:

            DialogBox(
                hInst,
                MAKEINTRESOURCE(IDD_ABOUTBOX),
                hWnd,
                About);

            break;


        case IDM_EXIT:

            DestroyWindow(hWnd);

            break;


        default:

            return DefWindowProc(
                hWnd,
                message,
                wParam,
                lParam);
        }
    }
    break;


    case WM_SIZE:
    {
        if (g_hEdit) {

            RECT rc;

            GetClientRect(
                hWnd,
                &rc);

            SetWindowPos(
                g_hEdit,
                nullptr,
                0,
                45,
                rc.right - rc.left,
                rc.bottom - 45,
                SWP_NOZORDER);
        }
    }
    break;


    case WM_APP + 1:
    {
        std::string* p =
            reinterpret_cast<std::string*>(lParam);

        if (p && g_hEdit) {

            std::string s = *p;

            int len =
                MultiByteToWideChar(
                    CP_UTF8,
                    0,
                    s.c_str(),
                    -1,
                    nullptr,
                    0);

            std::wstring w;

            w.resize(len);

            MultiByteToWideChar(
                CP_UTF8,
                0,
                s.c_str(),
                -1,
                &w[0],
                len);

            if (!w.empty() &&
                w.back() == L'\0') {

                w.pop_back();
            }

            int start =
                GetWindowTextLengthW(g_hEdit);

            SendMessageW(
                g_hEdit,
                EM_SETSEL,
                static_cast<WPARAM>(start),
                static_cast<LPARAM>(start));

            std::wstring out =
                w + L"\r\n";

            SendMessageW(
                g_hEdit,
                EM_REPLACESEL,
                FALSE,
                reinterpret_cast<LPARAM>(
                    out.c_str()));
        }

        delete p;
    }
    break;


    case WM_DESTROY:

        if (g_sniffer)
            g_sniffer->Stop();

        if (g_logger)
            g_logger->Stop();

        if (g_hInterfaceCombo) {

            int count =
                static_cast<int>(
                    SendMessage(
                        g_hInterfaceCombo,
                        CB_GETCOUNT,
                        0,
                        0));

            for (int i = 0; i < count; ++i) {

                auto* adapter =
                    reinterpret_cast<NetworkAdapter*>(
                        SendMessage(
                            g_hInterfaceCombo,
                            CB_GETITEMDATA,
                            i,
                            0));

                delete adapter;
            }
        }

        PostQuitMessage(0);

        break;


    default:

        return DefWindowProc(
            hWnd,
            message,
            wParam,
            lParam);
    }

    return 0;
}


// ------------------------------------------------------------
// About dialog
// ------------------------------------------------------------

INT_PTR CALLBACK About(
    HWND hDlg,
    UINT message,
    WPARAM wParam,
    LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);

    switch (message)
    {
    case WM_INITDIALOG:

        return static_cast<INT_PTR>(TRUE);


    case WM_COMMAND:

        if (LOWORD(wParam) == IDOK ||
            LOWORD(wParam) == IDCANCEL) {

            EndDialog(
                hDlg,
                LOWORD(wParam));

            return static_cast<INT_PTR>(TRUE);
        }

        break;
    }

    return static_cast<INT_PTR>(FALSE);
}
