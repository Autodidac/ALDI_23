#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// Simple POD for UI handles. One instance for the whole app.
struct OffSetReader_UI
{
    HWND hMain{}; // main window
    HWND hBtnOpen{};
    HWND hBtnPrev{};
    HWND hBtnNext{};
    HWND hEditCommand{};
    HWND hEditOutput{};
};

// Global UI accessor (implemented in ui_window.cpp)
OffSetReader_UI& ui_state();

// Main window procedure
LRESULT CALLBACK OffSetReader_WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
