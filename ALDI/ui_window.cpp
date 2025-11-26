#include "ui_window.hpp"

#include <commdlg.h>
#include <string>

import mod_commands;

#pragma comment(lib, "Comctl32.lib")

// Global UI instance
static ALDI_UI g_ui;

ALDI_UI& ui_state()
{
    return g_ui;
}

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

static void LayoutControls(HWND hwnd)
{
    RECT rc{};
    GetClientRect(hwnd, &rc);

    const int w = rc.right - rc.left;
    const int h = rc.bottom - rc.top;

    const int margin = 10;
    const int spacing = 10;
    const int btnW = 90;
    const int btnH = 26;

    // Row: [Open] [Prev] [Next] ... [ Command box ]
    MoveWindow(g_ui.hBtnOpen,
        margin, margin,
        btnW, btnH,
        TRUE);

    MoveWindow(g_ui.hBtnPrev,
        margin + (btnW + spacing), margin,
        btnW, btnH,
        TRUE);

    MoveWindow(g_ui.hBtnNext,
        margin + 2 * (btnW + spacing), margin,
        btnW, btnH,
        TRUE);

    const int cmdX = margin + 3 * (btnW + spacing) + 20;

    MoveWindow(g_ui.hEditCommand,
        cmdX, margin,
        w - cmdX - margin,
        btnH,
        TRUE);

    MoveWindow(g_ui.hEditOutput,
        margin,
        margin + btnH + spacing,
        w - margin * 2,
        h - (margin * 3 + btnH),
        TRUE);
}

// ---------------------------------------------------------------------------
// File dialog helper
// ---------------------------------------------------------------------------

static std::wstring OpenFileDialog(HWND owner)
{
    wchar_t buffer[MAX_PATH]{};

    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = owner;
    ofn.lpstrFilter = L"All Files\0*.*\0Executable\0*.exe\0";
    ofn.lpstrFile = buffer;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_EXPLORER |
        OFN_FILEMUSTEXIST |
        OFN_PATHMUSTEXIST;

    return GetOpenFileNameW(&ofn) ? buffer : std::wstring{};
}

// ---------------------------------------------------------------------------
// Bridge from module results to UI
// ---------------------------------------------------------------------------

static void ApplyCommandResult(const CommandResult& r)
{
    if (!g_ui.hEditOutput) return;

    switch (r.kind)
    {
    case CommandResultKind::None:
        break;

    case CommandResultKind::RefreshView:
    {
        const std::wstring text = render_main_view();
        SetWindowTextW(g_ui.hEditOutput, text.c_str());
        break;
    }

    case CommandResultKind::ReplaceTextW:
        SetWindowTextW(g_ui.hEditOutput, r.text.c_str());
        break;
    }
}

// ---------------------------------------------------------------------------
// Subclass for Enter key in command box
// ---------------------------------------------------------------------------

static WNDPROC g_oldCmdProc = nullptr;

static LRESULT CALLBACK CmdEditProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_KEYDOWN && wParam == VK_RETURN)
    {
        wchar_t buf[1024]{};
        GetWindowTextW(hwnd, buf, 1023);

        if (buf[0] != L'\0')
        {
            CommandResult r = ExecCommand(buf);
            ApplyCommandResult(r);
        }

        SetWindowTextW(hwnd, L"");
        return 0;
    }

    return CallWindowProcW(g_oldCmdProc, hwnd, msg, wParam, lParam);
}

// ---------------------------------------------------------------------------
// Window procedure
// ---------------------------------------------------------------------------

LRESULT CALLBACK ALDI_WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_CREATE:
    {
        g_ui.hMain = hwnd;

        g_ui.hBtnOpen = CreateWindowW(L"button", L"Open…",
            WS_CHILD | WS_VISIBLE, 0, 0, 0, 0,
            hwnd, (HMENU)1, nullptr, nullptr);

        g_ui.hBtnPrev = CreateWindowW(L"button", L"Prev",
            WS_CHILD | WS_VISIBLE, 0, 0, 0, 0,
            hwnd, (HMENU)2, nullptr, nullptr);

        g_ui.hBtnNext = CreateWindowW(L"button", L"Next",
            WS_CHILD | WS_VISIBLE, 0, 0, 0, 0,
            hwnd, (HMENU)3, nullptr, nullptr);

        g_ui.hEditCommand = CreateWindowW(
            L"edit", L"",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
            0, 0, 0, 0,
            hwnd, (HMENU)100, nullptr, nullptr);

        g_oldCmdProc = (WNDPROC)SetWindowLongPtrW(
            g_ui.hEditCommand, GWLP_WNDPROC,
            (LONG_PTR)CmdEditProc);

        g_ui.hEditOutput = CreateWindowW(
            L"edit", L"",
            WS_CHILD | WS_VISIBLE | WS_BORDER |
            ES_MULTILINE | ES_READONLY |
            ES_AUTOVSCROLL | WS_VSCROLL,
            0, 0, 0, 0,
            hwnd, nullptr, nullptr, nullptr);

        LayoutControls(hwnd);
        return 0;
    }

    case WM_SIZE:
        LayoutControls(hwnd);
        return 0;

    case WM_MOUSEWHEEL:
    {
        short delta = GET_WHEEL_DELTA_WPARAM(wParam);
        const int dir = (delta < 0) ? +1 : -1;

        scroll_pages(dir);

        CommandResult r{};
        r.kind = CommandResultKind::RefreshView;
        ApplyCommandResult(r);
        return 0;
    }

    case WM_COMMAND:
    {
        switch (LOWORD(wParam))
        {
        case 1: // open
        {
            std::wstring path = OpenFileDialog(hwnd);
            if (!path.empty())
            {
                if (open_file(path))
                {
                    ApplyCommandResult(
                        CommandResult{ CommandResultKind::RefreshView }
                    );
                }
            }
            return 0;
        }

        case 2: // prev
            scroll_pages(-1);
            ApplyCommandResult({ CommandResultKind::RefreshView });
            return 0;

        case 3: // next
            scroll_pages(+1);
            ApplyCommandResult({ CommandResultKind::RefreshView });
            return 0;
        }
        break;
    }

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}
