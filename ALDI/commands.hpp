#pragma once

#include <string>

import mod_commands;

namespace commands
{
    using Kind = CommandResultKind;
    using Result = CommandResult;

    inline Result exec(const std::wstring& line)
    {
        return ExecCommand(line);
    }

    inline bool open_file(const std::wstring& path)
    {
        return ::open_file(path);
    }

    inline void scroll_pages(int delta)
    {
        ::scroll_pages(delta);
    }

    inline std::wstring render_main_view()
    {
        return ::render_main_view();
    }
}
