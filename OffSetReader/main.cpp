#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>

#include "ui_window.hpp"

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

int APIENTRY wWinMain(HINSTANCE hInstance,
    HINSTANCE,
    LPWSTR,
    int nCmdShow)
{
    // Initialize common controls for nicer themed widgets
    INITCOMMONCONTROLSEX icc{};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    const wchar_t CLASS_NAME[] = L"OffSetReaderWinClass";

    WNDCLASSW wc{};
    wc.lpfnWndProc = OffSetReader_WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);

    if (!RegisterClassW(&wc))
        return 0;

    HWND hwnd = CreateWindowW(
        CLASS_NAME,
        L"OffSetReader — Zydis 4.1.1 Edition",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT,
        860, 680,
        nullptr, nullptr,
        hInstance, nullptr
    );

    if (!hwnd)
        return 0;

    ui_state().hMain = hwnd;

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return static_cast<int>(msg.wParam);
}



//// OffSetReader.cpp — C++23 Win32 RE Tool using Zydis 4.1.1
////
//// - Hex viewer
//// - Pattern search
//// - Patch & templates
//// - Disassembler (Zydis 4.1.1)
//// - VFT inspector
////
//// Commands (type into Command box, press Enter):
////   patch <off> <hex>          file patch
////   label <off> <name>         bookmark
////   goto <off>                 jump page
////   find <hex>                 find byte pattern
////   findnext                   next hit
////   savetpl <name> <off> <hex> save patch template
////   applytpl <name> [off]      apply template
////   mempatch <pid> <addr> <hex> write to another process
////   dump <off> <size>          hex dump region
////   disasm <off> <size>        disassemble region
////   vft <off> <count>          treat region as vtable of 8-byte RVAs
////
//// Offsets accept absolute and relative forms: 0x1234, 1234, +0x20, -16, etc.
//// ---------------------------------------------------------------------
//
//#define WIN32_LEAN_AND_MEAN
//#include <windows.h>
//#include <commdlg.h>
//
//#include <string>
//#include <vector>
//#include <fstream>
//#include <sstream>
//#include <iomanip>
//#include <span>
//#include <algorithm>
//#include <cstdint>
//#include <cstddef>
//#include <cstring>
//
//// Zydis 4.1.1
//#include <Zycore/Types.h>
//#include <Zydis/Zydis.h>
//
//// ---------------------------------------------------------------------
//// Small helpers
//// ---------------------------------------------------------------------
//template<typename T>
//T mmin(T a, T b) { return (std::min)(a, b); }
//
//std::wstring trim(const std::wstring& s)
//{
//    std::size_t a = 0;
//    std::size_t b = s.size();
//    while (a < b && iswspace(s[a])) ++a;
//    while (b > a && iswspace(s[b - 1])) --b;
//    return s.substr(a, b - a);
//}
//
//std::vector<std::wstring> split_ws(const std::wstring& s)
//{
//    std::vector<std::wstring> out;
//    std::wstring cur;
//    for (wchar_t c : s) {
//        if (iswspace(c)) {
//            if (!cur.empty()) { out.push_back(cur); cur.clear(); }
//        }
//        else {
//            cur.push_back(c);
//        }
//    }
//    if (!cur.empty()) out.push_back(cur);
//    return out;
//}
//
//// ---------------------------------------------------------------------
//// Windows Open File Dialog
//// ---------------------------------------------------------------------
//std::wstring file_dialog(HWND owner)
//{
//    wchar_t buf[MAX_PATH] = {};
//
//    OPENFILENAMEW ofn{};
//    ofn.lStructSize = sizeof(ofn);
//    ofn.hwndOwner = owner;
//    ofn.lpstrFilter = L"All Files\0*.*\0Executable\0*.exe\0";
//    ofn.lpstrFile = buf;
//    ofn.nMaxFile = MAX_PATH;
//    ofn.Flags = OFN_EXPLORER |
//        OFN_FILEMUSTEXIST |
//        OFN_PATHMUSTEXIST;
//
//    if (GetOpenFileNameW(&ofn))
//        return buf;
//
//    return L"";
//}
//
//// ---------------------------------------------------------------------
//// Binary file
//// ---------------------------------------------------------------------
//class BinaryFile {
//public:
//    bool load(const std::wstring& path)
//    {
//        std::ifstream f(path, std::ios::binary);
//        if (!f) return false;
//
//        f.seekg(0, std::ios::end);
//        auto pos = f.tellg();
//        if (pos < 0) return false;
//
//        size_ = static_cast<std::size_t>(pos);
//        buffer_.resize(size_);
//
//        f.seekg(0, std::ios::beg);
//        if (!f.read(reinterpret_cast<char*>(buffer_.data()),
//            static_cast<std::streamsize>(size_)))
//            return false;
//
//        path_ = path;
//        return true;
//    }
//
//    bool patch(std::size_t off, const void* data, std::size_t len)
//    {
//        if (off + len > size_) return false;
//
//        std::memcpy(buffer_.data() + off, data, len);
//
//        std::fstream f(path_, std::ios::binary | std::ios::in | std::ios::out);
//        if (!f) return false;
//
//        f.seekp(static_cast<std::streamoff>(off));
//        f.write(reinterpret_cast<const char*>(data),
//            static_cast<std::streamsize>(len));
//        return f.good();
//    }
//
//    std::span<const std::byte> bytes() const noexcept { return buffer_; }
//    std::size_t size() const noexcept { return size_; }
//    const std::wstring& path() const noexcept { return path_; }
//
//private:
//    std::wstring           path_;
//    std::vector<std::byte> buffer_;
//    std::size_t            size_ = 0;
//};
//
//// ---------------------------------------------------------------------
//// Patch templates & bookmarks
//// ---------------------------------------------------------------------
//struct OffsetEntry {
//    std::size_t offset{};
//    std::wstring label;
//};
//
//struct PatchTemplate {
//    std::wstring name;
//    std::size_t offset{};
//    std::vector<unsigned char> bytes;
//};
//
//// ---------------------------------------------------------------------
//// Globals
//// ---------------------------------------------------------------------
//BinaryFile g_file;
//std::vector<OffsetEntry>    g_offsets;
//std::vector<PatchTemplate>  g_templates;
//
//constexpr std::size_t PAGE_SIZE = 4096;
//std::size_t g_pageOffset = 0;
//
//// last-find state
//bool                     g_haveLastFind = false;
//std::size_t              g_lastFindOffset = 0;
//std::vector<unsigned char> g_lastPattern;
//
//HWND    g_hEdit = nullptr;
//HWND    g_hCmd = nullptr;
//WNDPROC g_oldCmdProc = nullptr;
//
//// ---------------------------------------------------------------------
//// Parse hex bytes (e.g. "48 8B 05 ?? ?? ?? ??")
//// (non-hex chars are stripped; odd trailing nibble is dropped)
//// ---------------------------------------------------------------------
//std::vector<unsigned char> parse_hex_bytes(std::wstring hex)
//{
//    std::vector<unsigned char> out;
//    std::wstring cleaned;
//
//    for (wchar_t c : hex)
//        if (!iswspace(c)) cleaned.push_back(c);
//
//    auto is_hex = [](wchar_t c) {
//        return (c >= L'0' && c <= L'9') ||
//            (c >= L'a' && c <= L'f') ||
//            (c >= L'A' && c <= L'F');
//        };
//
//    std::wstring h2;
//    for (auto c : cleaned)
//        if (is_hex(c)) h2.push_back(c);
//
//    if (h2.size() & 1) h2.pop_back();
//
//    for (std::size_t i = 0; i + 1 < h2.size(); i += 2) {
//        unsigned v = std::stoul(h2.substr(i, 2), nullptr, 16);
//        out.push_back(static_cast<unsigned char>(v));
//    }
//
//    return out;
//}
//
//// ---------------------------------------------------------------------
//// Offsets: absolute or relative (+0x10, -20)
//// ---------------------------------------------------------------------
//std::size_t parse_offset(const std::wstring& s)
//{
//    auto t = trim(s);
//    if (t.empty())
//        throw std::runtime_error("empty offset");
//
//    if (t[0] == L'+' || t[0] == L'-') {
//        long long delta = std::stoll(t, nullptr, 0);
//        long long base = static_cast<long long>(g_pageOffset);
//        long long v = base + delta;
//        if (v < 0) v = 0;
//        return static_cast<std::size_t>(v);
//    }
//    return static_cast<std::size_t>(std::stoull(t, nullptr, 0));
//}
//
//// ---------------------------------------------------------------------
//// Hex viewer
//// ---------------------------------------------------------------------
//std::wstring hex_page(std::span<const std::byte> data,
//    std::size_t off,
//    std::size_t cnt)
//{
//    std::size_t end = mmin(off + cnt, data.size());
//    std::size_t n = end - off;
//
//    std::wstringstream out;
//
//    for (std::size_t i = 0; i < n; i += 16)
//    {
//        std::size_t addr = off + i;
//
//        out << std::hex << std::setw(8) << std::setfill(L'0')
//            << addr << L"  ";
//
//        for (std::size_t j = 0; j < 16; ++j)
//        {
//            if (i + j < n) {
//                unsigned v = std::to_integer<unsigned char>(data[off + i + j]);
//                out << std::setw(2) << v << L" ";
//            }
//            else {
//                out << L"   ";
//            }
//        }
//
//        out << L" ";
//
//        for (std::size_t j = 0; j < 16 && (i + j) < n; ++j)
//        {
//            unsigned char c = std::to_integer<unsigned char>(data[off + i + j]);
//            out << ((c >= 32 && c < 127) ? wchar_t(c) : L'.');
//        }
//        out << L"\r\n";
//    }
//    return out.str();
//}
//
//// ---------------------------------------------------------------------
//// Pattern search (naive but fine for small-ish files)
//// ---------------------------------------------------------------------
//std::size_t find_pattern(std::span<const std::byte> data,
//    const std::vector<unsigned char>& pat,
//    std::size_t start)
//{
//    if (pat.empty() || start >= data.size()) return std::string::npos;
//
//    const std::size_t n = data.size();
//    const std::size_t m = pat.size();
//    if (m > n) return std::string::npos;
//
//    for (std::size_t i = start; i + m <= n; ++i) {
//        if (std::memcmp(data.data() + i, pat.data(), m) == 0)
//            return i;
//    }
//    return std::string::npos;
//}
//
//// ---------------------------------------------------------------------
//// Disassemble region using Zydis 4.x (decoder + formatter)
//// ---------------------------------------------------------------------
//std::wstring disasm_region(
//    std::span<const std::byte> data,
//    std::size_t offset,
//    std::size_t size,
//    std::uint64_t baseAddress)
//{
//    const std::size_t end = mmin(offset + size, data.size());
//    if (end <= offset)
//        return L"(empty)\r\n";
//
//    // --- Decoder ---
//    ZydisDecoder decoder{};
//    ZydisDecoderInit(
//        &decoder,
//        ZYDIS_MACHINE_MODE_LONG_64,
//        ZYDIS_STACK_WIDTH_64);
//
//    // --- Formatter ---
//    ZydisFormatter formatter{};
//    ZydisFormatterInit(
//        &formatter,
//        ZYDIS_FORMATTER_STYLE_INTEL);
//
//    std::wstringstream out;
//    out << L"Disasm @ offset 0x"
//        << std::hex << offset << L"\r\n\r\n";
//
//    ZyanUSize cur = 0;
//    ZyanUSize total = static_cast<ZyanUSize>(end - offset);
//
//    while (cur < total)
//    {
//        ZydisDecodedInstruction inst{};
//        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]{};
//
//        // Decode FULL instruction + operands
//        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
//            &decoder,
//            data.data() + offset + cur,
//            total - cur,
//            &inst,
//            ops)))
//        {
//            break;
//        }
//
//        char buf[256]{};
//        ZyanU64 addr = baseAddress + offset + cur;
//
//        // Format instruction
//        ZydisFormatterFormatInstruction(
//            &formatter,
//            &inst,
//            ops,
//            inst.operand_count_visible,
//            buf,
//            sizeof(buf),
//            addr,
//            nullptr);
//
//        // Convert to UTF-16
//        std::wstring ws;
//        for (char c : std::string(buf))
//        {
//            if (!c) break;
//            ws.push_back((unsigned char)c);
//        }
//
//        out << L"0x" << std::hex << addr
//            << L"  " << ws << L"\r\n";
//
//        cur += inst.length;
//    }
//
//    return out.str();
//}
//
//
//// ---------------------------------------------------------------------
//// Dump command
//// ---------------------------------------------------------------------
//std::wstring hex_dump_region(std::span<const std::byte> data,
//    std::size_t off,
//    std::size_t size)
//{
//    std::size_t end = mmin(off + size, data.size());
//    std::size_t n = end - off;
//
//    std::wstringstream out;
//    out << L"Dump @ 0x" << std::hex << off << L", size "
//        << std::dec << n << L"\r\n\r\n";
//    out << hex_page(data, off, n);
//    return out.str();
//}
//
//// ---------------------------------------------------------------------
//// Memory patch (own process only)
//// ---------------------------------------------------------------------
//bool mem_patch(DWORD pid, std::uintptr_t addr,
//    const std::vector<unsigned char>& bytes)
//{
//    HANDLE h = OpenProcess(PROCESS_VM_OPERATION |
//        PROCESS_VM_WRITE |
//        PROCESS_VM_READ,
//        FALSE, pid);
//    if (!h) return false;
//
//    SIZE_T written = 0;
//    BOOL ok = WriteProcessMemory(
//        h,
//        reinterpret_cast<LPVOID>(addr),
//        bytes.data(),
//        bytes.size(),
//        &written);
//
//    CloseHandle(h);
//    return ok && written == bytes.size();
//}
//
//// ---------------------------------------------------------------------
//// VFT disassembly (RVA-style, simplistic)
//// ---------------------------------------------------------------------
//std::wstring disasm_vft(std::span<const std::byte> data,
//    std::size_t offset,
//    std::size_t count,
//    std::uint64_t base)
//{
//    std::wstringstream out;
//
//    out << L"VFT @ file offset 0x" << std::hex << offset
//        << L", count " << std::dec << count << L"\r\n\r\n";
//
//    if (offset + count * 8 > data.size()) {
//        out << L"(out of range)\r\n";
//        return out.str();
//    }
//
//    for (std::size_t i = 0; i < count; ++i)
//    {
//        std::size_t off = offset + i * 8;
//        std::uint64_t rva{};
//        std::memcpy(&rva, data.data() + off, 8);
//
//        out << L"[#" << i << L"] RVA 0x" << std::hex << rva;
//
//        if (rva < data.size())
//        {
//            out << L" (file off 0x" << rva << L")\r\n";
//            out << disasm_region(data,
//                static_cast<std::size_t>(rva),
//                64,
//                base + rva) << L"\r\n";
//        }
//        else {
//            out << L" (out of file range)\r\n";
//        }
//    }
//
//    return out.str();
//}
//
//// ---------------------------------------------------------------------
//// Refresh main viewer
//// ---------------------------------------------------------------------
//void refresh_view()
//{
//    if (!g_hEdit) return;
//
//    if (g_file.size() == 0) {
//        SetWindowTextW(g_hEdit, L"No file loaded.");
//        return;
//    }
//
//    if (g_pageOffset >= g_file.size())
//        g_pageOffset = (g_file.size() / PAGE_SIZE) * PAGE_SIZE;
//
//    auto bytes = g_file.bytes();
//
//    std::size_t page_start = g_pageOffset;
//    std::size_t page_end = mmin(g_pageOffset + PAGE_SIZE, g_file.size());
//
//    std::wstringstream out;
//
//    out << L"File: " << g_file.path() << L"\r\n";
//    out << L"Size: " << g_file.size() << L" bytes\r\n";
//    out << L"Page: " << page_start << L" - "
//        << (page_end ? page_end - 1 : 0) << L"\r\n\r\n";
//
//    out << L"[Bookmarks]\r\n";
//    for (auto& e : g_offsets)
//    {
//        out << L"0x" << std::hex << e.offset << std::dec
//            << L" = " << e.label << L"\r\n";
//    }
//
//    out << L"\r\n[Hex]\r\n";
//    out << hex_page(bytes, page_start, PAGE_SIZE);
//
//    SetWindowTextW(g_hEdit, out.str().c_str());
//}
//
//// ---------------------------------------------------------------------
//// Command execution
//// ---------------------------------------------------------------------
//void exec_command(const std::wstring& raw)
//{
//    auto line = trim(raw);
//    if (line.empty()) return;
//
//    auto tok = split_ws(line);
//    if (tok.empty()) return;
//
//    std::wstring cmd = tok[0];
//    for (auto& c : cmd) c = towlower(c);
//
//    std::wstring result;
//
//    try {
//        if (cmd == L"patch") {
//            if (tok.size() < 3) return;
//            std::size_t off = parse_offset(tok[1]);
//
//            auto pos = line.find(tok[2]);
//            auto hex = line.substr(pos);
//            auto bytes = parse_hex_bytes(hex);
//
//            g_file.patch(off, bytes.data(), bytes.size());
//            g_haveLastFind = false;
//            refresh_view();
//        }
//        else if (cmd == L"label") {
//            if (tok.size() < 3) return;
//            std::size_t off = parse_offset(tok[1]);
//
//            auto p = line.find(tok[2]);
//            std::wstring name = trim(line.substr(p));
//
//            g_offsets.push_back({ off, name });
//            refresh_view();
//        }
//        else if (cmd == L"goto") {
//            if (tok.size() < 2) return;
//
//            std::size_t off = parse_offset(tok[1]);
//            if (off >= g_file.size())
//                off = g_file.size() ? g_file.size() - 1 : 0;
//
//            g_pageOffset = (off / PAGE_SIZE) * PAGE_SIZE;
//            refresh_view();
//        }
//        else if (cmd == L"find") {
//            if (tok.size() < 2) return;
//
//            auto pos = line.find(tok[1]);
//            auto hex = line.substr(pos);
//            auto pat = parse_hex_bytes(hex);
//
//            auto data = g_file.bytes();
//            auto hit = find_pattern(data, pat, 0);
//
//            if (hit != std::string::npos) {
//                g_lastPattern = pat;
//                g_haveLastFind = true;
//                g_lastFindOffset = hit;
//                g_pageOffset = (hit / PAGE_SIZE) * PAGE_SIZE;
//                refresh_view();
//            }
//        }
//        else if (cmd == L"findnext") {
//            if (!g_haveLastFind) return;
//
//            auto data = g_file.bytes();
//            auto hit = find_pattern(data,
//                g_lastPattern,
//                g_lastFindOffset + 1);
//
//            if (hit != std::string::npos) {
//                g_lastFindOffset = hit;
//                g_pageOffset = (hit / PAGE_SIZE) * PAGE_SIZE;
//                refresh_view();
//            }
//        }
//        else if (cmd == L"savetpl") {
//            if (tok.size() < 4) return;
//
//            std::wstring name = tok[1];
//            std::size_t  off = parse_offset(tok[2]);
//
//            auto p = line.find(tok[3]);
//            auto hex = line.substr(p);
//            auto bytes = parse_hex_bytes(hex);
//
//            auto it = std::find_if(g_templates.begin(), g_templates.end(),
//                [&](auto& t) { return t.name == name; });
//
//            if (it != g_templates.end()) {
//                it->offset = off;
//                it->bytes = bytes;
//            }
//            else {
//                g_templates.push_back({ name, off, bytes });
//            }
//        }
//        else if (cmd == L"applytpl") {
//            if (tok.size() < 2) return;
//
//            std::wstring name = tok[1];
//            auto it = std::find_if(g_templates.begin(), g_templates.end(),
//                [&](auto& t) { return t.name == name; });
//            if (it == g_templates.end()) return;
//
//            std::size_t off = it->offset;
//            if (tok.size() >= 3)
//                off = parse_offset(tok[2]);
//
//            g_file.patch(off, it->bytes.data(), it->bytes.size());
//            refresh_view();
//        }
//        else if (cmd == L"mempatch") {
//            if (tok.size() < 4) return;
//
//            DWORD pid = static_cast<DWORD>(std::stoul(tok[1], nullptr, 0));
//            std::uintptr_t addr =
//                static_cast<std::uintptr_t>(std::stoull(tok[2], nullptr, 0));
//
//            auto p = line.find(tok[3]);
//            auto hex = line.substr(p);
//            auto bytes = parse_hex_bytes(hex);
//
//            mem_patch(pid, addr, bytes);
//        }
//        else if (cmd == L"dump") {
//            if (tok.size() < 3) return;
//
//            std::size_t off = parse_offset(tok[1]);
//            std::size_t sz = static_cast<std::size_t>(
//                std::stoull(tok[2], nullptr, 0));
//
//            result = hex_dump_region(g_file.bytes(), off, sz);
//            SetWindowTextW(g_hEdit, result.c_str());
//        }
//        else if (cmd == L"disasm") {
//            if (tok.size() < 3) return;
//
//            std::size_t off = parse_offset(tok[1]);
//            std::size_t sz = static_cast<std::size_t>(
//                std::stoull(tok[2], nullptr, 0));
//
//            result = disasm_region(g_file.bytes(), off, sz, 0);
//            SetWindowTextW(g_hEdit, result.c_str());
//        }
//        else if (cmd == L"vft") {
//            if (tok.size() < 3) return;
//
//            std::size_t off = parse_offset(tok[1]);
//            std::size_t cnt = static_cast<std::size_t>(
//                std::stoull(tok[2], nullptr, 0));
//
//            result = disasm_vft(g_file.bytes(), off, cnt, 0);
//            SetWindowTextW(g_hEdit, result.c_str());
//        }
//    }
//    catch (...) {
//        // swallow; keep UI simple for now
//    }
//}
//
//// ---------------------------------------------------------------------
//// Command input window proc
//// ---------------------------------------------------------------------
//LRESULT CALLBACK CmdEditProc(HWND h, UINT m,
//    WPARAM w, LPARAM l)
//{
//    if (m == WM_KEYDOWN && w == VK_RETURN)
//    {
//        wchar_t buf[1024]{};
//        GetWindowTextW(h, buf, 1023);
//        exec_command(buf);
//        SetWindowTextW(h, L"");
//        return 0;
//    }
//    return CallWindowProcW(g_oldCmdProc, h, m, w, l);
//}
//
//// ---------------------------------------------------------------------
//// Main window
//// ---------------------------------------------------------------------
//LRESULT CALLBACK WndProc(HWND hwnd, UINT msg,
//    WPARAM wParam, LPARAM lParam)
//{
//    switch (msg)
//    {
//    case WM_CREATE:
//    {
//        CreateWindowW(L"button", L"Open...",
//            WS_CHILD | WS_VISIBLE,
//            10, 10, 80, 24,
//            hwnd, (HMENU)1, nullptr, nullptr);
//
//        CreateWindowW(L"button", L"Prev Page",
//            WS_CHILD | WS_VISIBLE,
//            100, 10, 100, 24,
//            hwnd, (HMENU)2, nullptr, nullptr);
//
//        CreateWindowW(L"button", L"Next Page",
//            WS_CHILD | WS_VISIBLE,
//            210, 10, 100, 24,
//            hwnd, (HMENU)3, nullptr, nullptr);
//
//        CreateWindowW(L"static", L"Command:",
//            WS_CHILD | WS_VISIBLE,
//            330, 10, 70, 20,
//            hwnd, nullptr, nullptr, nullptr);
//
//        g_hCmd = CreateWindowW(L"edit", L"",
//            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
//            410, 10, 380, 24,
//            hwnd, (HMENU)100, nullptr, nullptr);
//
//        g_oldCmdProc = reinterpret_cast<WNDPROC>(
//            SetWindowLongPtrW(
//                g_hCmd, GWLP_WNDPROC,
//                reinterpret_cast<LONG_PTR>(CmdEditProc)));
//
//        g_hEdit = CreateWindowW(L"edit", L"",
//            WS_CHILD | WS_VISIBLE | WS_BORDER |
//            ES_MULTILINE | ES_READONLY |
//            ES_AUTOVSCROLL | WS_VSCROLL,
//            10, 45, 780, 545,
//            hwnd, nullptr, nullptr, nullptr);
//        break;
//    }
//
//    case WM_SIZE:
//    {
//        if (g_hCmd && g_hEdit)
//        {
//            int w = LOWORD(lParam);
//            int h = HIWORD(lParam);
//
//            MoveWindow(g_hCmd, 410, 10, w - 420, 24, TRUE);
//            MoveWindow(g_hEdit, 10, 45, w - 20, h - 55, TRUE);
//        }
//        break;
//    }
//
//    case WM_MOUSEWHEEL:
//    {
//        if (GET_WHEEL_DELTA_WPARAM(wParam) < 0)
//            g_pageOffset = mmin(
//                g_pageOffset + PAGE_SIZE,
//                g_file.size());
//        else
//            g_pageOffset =
//            (g_pageOffset >= PAGE_SIZE)
//            ? g_pageOffset - PAGE_SIZE
//            : 0;
//
//        refresh_view();
//        break;
//    }
//
//    case WM_COMMAND:
//    {
//        switch (LOWORD(wParam))
//        {
//        case 1:
//        {
//            auto path = file_dialog(hwnd);
//            if (!path.empty() && g_file.load(path))
//            {
//                g_offsets.clear();
//                g_templates.clear();
//                g_pageOffset = 0;
//                g_haveLastFind = false;
//                g_lastPattern.clear();
//                refresh_view();
//            }
//            break;
//        }
//        case 2:
//            g_pageOffset =
//                (g_pageOffset >= PAGE_SIZE)
//                ? g_pageOffset - PAGE_SIZE
//                : 0;
//            refresh_view();
//            break;
//
//        case 3:
//            g_pageOffset = mmin(
//                g_pageOffset + PAGE_SIZE,
//                g_file.size());
//            refresh_view();
//            break;
//        }
//        break;
//    }
//
//    case WM_DESTROY:
//        PostQuitMessage(0);
//        break;
//    }
//
//    return DefWindowProcW(hwnd, msg, wParam, lParam);
//}
//
//// ---------------------------------------------------------------------
//// Entry
//// ---------------------------------------------------------------------
//int APIENTRY wWinMain(HINSTANCE hInst,
//    HINSTANCE, LPWSTR, int)
//{
//    const wchar_t CLASS[] = L"OffSetReaderWin";
//
//    WNDCLASSW wc{};
//    wc.lpfnWndProc = WndProc;
//    wc.hInstance = hInst;
//    wc.lpszClassName = CLASS;
//    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
//
//    RegisterClassW(&wc);
//
//    CreateWindowW(CLASS,
//        L"OffSetReader — Zydis 4.1.1 Edition",
//        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
//        CW_USEDEFAULT, CW_USEDEFAULT,
//        860, 680,
//        nullptr, nullptr, hInst, nullptr);
//
//    MSG msg{};
//    while (GetMessageW(&msg, nullptr, 0, 0))
//    {
//        TranslateMessage(&msg);
//        DispatchMessageW(&msg);
//    }
//    return 0;
//}
