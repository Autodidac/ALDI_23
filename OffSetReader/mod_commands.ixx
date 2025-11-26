export module mod_commands;

import mod_binary_file;
import mod_patterns;
import mod_hex;
import mod_disasm;

import <string>;
import <vector>;
import <algorithm>;
import <cstdint>;
import <cstddef>;
import <cwctype>;
import <sstream>;
import <stdexcept>;
import <span>;

// ============================================================
// INTERNAL STATE (NOT EXPORTED)
// ============================================================

namespace state
{
    inline std::size_t page_offset = 0;

    inline bool         have_last_find = false;
    inline std::size_t  last_find_offset = 0;
    export std::vector<unsigned char> last_pattern;

    struct Bookmark
    {
        std::size_t  offset{};
        std::wstring label{};
    };
    export std::vector<Bookmark> bookmarks;

    struct Template
    {
        std::wstring            name;
        std::size_t             offset{};
        std::vector<unsigned char> bytes;
    };
    export std::vector<Template> templates;
}

// ============================================================
// PUBLIC API
// ============================================================

export enum class CommandResultKind
{
    None,
    RefreshView,
    ReplaceTextW
};

export struct CommandResult
{
    CommandResultKind kind{ CommandResultKind::None };
    std::wstring      text{};
};

export std::wstring render_main_view();
export void         scroll_pages(int delta);
export bool         open_file(const std::wstring& path);
export CommandResult ExecCommand(const std::wstring& raw);

// ============================================================
// INTERNAL HELPERS
// ============================================================

static std::wstring Trim(const std::wstring& s)
{
    std::size_t a = 0, b = s.size();
    while (a < b && iswspace(s[a])) ++a;
    while (b > a && iswspace(s[b - 1])) --b;
    return s.substr(a, b - a);
}

static std::vector<std::wstring> SplitWS(const std::wstring& s)
{
    std::vector<std::wstring> out;
    std::wstring cur;

    for (wchar_t c : s)
    {
        if (iswspace(c))
        {
            if (!cur.empty())
            {
                out.push_back(cur);
                cur.clear();
            }
        }
        else
        {
            cur.push_back(c);
        }
    }

    if (!cur.empty())
        out.push_back(cur);

    return out;
}

static std::size_t ParseOffset(const std::wstring& s)
{
    auto t = Trim(s);
    if (t.empty())
        return 0;

    if (t[0] == L'+' || t[0] == L'-')
    {
        long long d = std::stoll(t, nullptr, 0);
        long long base = static_cast<long long>(state::page_offset);
        long long v = base + d;
        if (v < 0) v = 0;
        return static_cast<std::size_t>(v);
    }

    return static_cast<std::size_t>(std::stoull(t, nullptr, 0));
}

static std::wstring RenderFullPage()
{
    std::wstringstream o;

    o << L"File: " << CorePath() << L"\r\n";
    o << L"Size: " << CoreSize() << L" bytes\r\n";

    constexpr std::size_t PAGE = 4096;

    auto start = state::page_offset;
    auto end = std::min(start + PAGE, CoreSize());

    o << L"Page: " << start << L" - " << (end ? end - 1 : 0) << L"\r\n";

    if (!state::bookmarks.empty())
    {
        o << L"\r\n[Bookmarks]\r\n";
        for (const auto& b : state::bookmarks)
            o << L"0x" << std::hex << b.offset << L"  " << b.label << L"\r\n";
        o << L"\r\n";
    }

    o << L"[Hex]\r\n";
    o << HexPage(CoreBytes(), start, PAGE);

    return o.str();
}

// ============================================================
// PUBLIC API IMPLEMENTATION
// ============================================================

export std::wstring render_main_view()
{
    return RenderFullPage();
}

export void scroll_pages(int delta)
{
    constexpr std::size_t PAGE = 4096;

    if (delta > 0)
    {
        state::page_offset =
            std::min(state::page_offset + PAGE, CoreSize());
    }
    else if (delta < 0)
    {
        if (state::page_offset >= PAGE)
            state::page_offset -= PAGE;
        else
            state::page_offset = 0;
    }
}

export bool open_file(const std::wstring& path)
{
    if (!CoreLoadFile(path))
        return false;

    state::page_offset = 0;
    state::have_last_find = false;
    state::last_pattern.clear();
    state::bookmarks.clear();
    state::templates.clear();
    return true;
}

// ============================================================
// COMMAND EXECUTION
// ============================================================

export CommandResult ExecCommand(const std::wstring& raw)
{
    std::wstring line = Trim(raw);
    if (line.empty())
        return {};

    auto tok = SplitWS(line);
    if (tok.empty())
        return {};

    std::wstring cmd = tok[0];
    std::transform(cmd.begin(), cmd.end(), cmd.begin(),
        [](wchar_t c) { return std::towlower(c); });

    try
    {
        // -----------------------------------------------------
        // Navigation: prev / next / scroll
        // -----------------------------------------------------
        if (cmd == L"prev")
        {
            scroll_pages(-1);
            return { CommandResultKind::RefreshView, {} };
        }

        if (cmd == L"next")
        {
            scroll_pages(+1);
            return { CommandResultKind::RefreshView, {} };
        }

        if (cmd == L"scroll")
        {
            if (tok.size() < 2) return {};
            scroll_pages(tok[1] == L"+" ? +1 : -1);
            return { CommandResultKind::RefreshView, {} };
        }

        // -----------------------------------------------------
        // goto
        // -----------------------------------------------------
        if (cmd == L"goto")
        {
            if (tok.size() < 2) return {};
            auto off = ParseOffset(tok[1]);

            constexpr std::size_t PAGE = 4096;
            state::page_offset = (off / PAGE) * PAGE;

            return { CommandResultKind::RefreshView, {} };
        }

        // -----------------------------------------------------
        // dump
        // -----------------------------------------------------
        if (cmd == L"dump")
        {
            if (tok.size() < 3) return {};

            auto off = ParseOffset(tok[1]);
            auto sz = std::stoull(tok[2], nullptr, 0);

            auto txt = HexDumpRegion(CoreBytes(), off, sz);
            return { CommandResultKind::ReplaceTextW, txt };
        }

        // -----------------------------------------------------
        // disasm
        // -----------------------------------------------------
        if (cmd == L"disasm")
        {
            if (tok.size() < 3) return {};

            auto off = ParseOffset(tok[1]);
            auto sz = std::stoull(tok[2], nullptr, 0);

            auto txt = DisasmRegion(CoreBytes(), off, sz, 0);
            return { CommandResultKind::ReplaceTextW, txt };
        }

        // -----------------------------------------------------
        // vft
        // -----------------------------------------------------
        if (cmd == L"vft")
        {
            if (tok.size() < 3) return {};

            auto off = ParseOffset(tok[1]);
            auto cnt = std::stoull(tok[2], nullptr, 0);

            auto txt = DisasmVFT(CoreBytes(), off, cnt, 0);
            return { CommandResultKind::ReplaceTextW, txt };
        }

        // -----------------------------------------------------
        // find
        // -----------------------------------------------------
        if (cmd == L"find")
        {
            if (tok.size() < 2) return {};

            auto pos = line.find(tok[1]);
            auto hex = line.substr(pos);
            auto pat = ParseHexBytes(hex);

            auto hit = FindPattern(CoreBytes(), pat, 0);

            if (hit != SIZE_MAX)
            {
                state::last_pattern = pat;
                state::last_find_offset = hit;
                state::have_last_find = true;

                constexpr std::size_t PAGE = 4096;
                state::page_offset = (hit / PAGE) * PAGE;

                return { CommandResultKind::RefreshView, {} };
            }

            return { CommandResultKind::ReplaceTextW, L"(not found)\r\n" };
        }

        // -----------------------------------------------------
        // findnext
        // -----------------------------------------------------
        if (cmd == L"findnext")
        {
            if (!state::have_last_find) return {};

            auto hit = FindPattern(
                CoreBytes(),
                state::last_pattern,
                state::last_find_offset + 1
            );

            if (hit != SIZE_MAX)
            {
                state::last_find_offset = hit;

                constexpr std::size_t PAGE = 4096;
                state::page_offset = (hit / PAGE) * PAGE;

                return { CommandResultKind::RefreshView, {} };
            }

            return { CommandResultKind::ReplaceTextW, L"(not found)\r\n" };
        }

        // -----------------------------------------------------
        // patch
        // -----------------------------------------------------
        if (cmd == L"patch")
        {
            if (tok.size() < 3) return {};

            auto off = ParseOffset(tok[1]);
            auto pos = line.find(tok[2]);
            auto hex = line.substr(pos);
            auto bytes = ParseHexBytes(hex);

            CorePatchFile(off, bytes);
            return { CommandResultKind::RefreshView, {} };
        }

        // -----------------------------------------------------
        // savetpl
        // -----------------------------------------------------
        if (cmd == L"savetpl")
        {
            if (tok.size() < 4) return {};

            const auto& name = tok[1];
            auto        off = ParseOffset(tok[2]);

            auto pos = line.find(tok[3]);
            auto hex = line.substr(pos);
            auto bytes = ParseHexBytes(hex);

            auto it = std::find_if(
                state::templates.begin(),
                state::templates.end(),
                [&](const state::Template& t) { return t.name == name; }
            );

            if (it != state::templates.end())
            {
                it->offset = off;
                it->bytes = bytes;
            }
            else
            {
                state::templates.push_back({ name, off, bytes });
            }

            return {};
        }

        // -----------------------------------------------------
        // applytpl
        // -----------------------------------------------------
        if (cmd == L"applytpl")
        {
            if (tok.size() < 2) return {};

            const auto& name = tok[1];

            auto it = std::find_if(
                state::templates.begin(),
                state::templates.end(),
                [&](const state::Template& t) { return t.name == name; }
            );

            if (it == state::templates.end())
                return {};

            auto off = it->offset;
            if (tok.size() >= 3)
                off = ParseOffset(tok[2]);

            CorePatchFile(off, it->bytes);
            return { CommandResultKind::RefreshView, {} };
        }

        // -----------------------------------------------------
        // open: UI does dialog, we just tell it to refresh
        // -----------------------------------------------------
        if (cmd == L"open")
        {
            return { CommandResultKind::RefreshView, {} };
        }
    }
    catch (...)
    {
        return { CommandResultKind::ReplaceTextW, L"(command error)\r\n" };
    }

    return {};
}
