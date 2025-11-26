export module mod_patterns;

import <string>;
import <vector>;
import <cstddef>;
import <cstdint>;
import <cwctype>;
import <stdexcept>;
import <span>;

// Parse hex bytes from something like:
//   L"48 8B 05 39 00 13 00"
//   L"48 8B 05 ?? ?? ?? ??"
// Non-hex chars are stripped; odd trailing nibble is dropped.
// "??" are simply ignored (treated as wildcards upstream if desired).
export std::vector<unsigned char> ParseHexBytes(const std::wstring& hex)
{
    std::wstring cleaned;
    cleaned.reserve(hex.size());

    for (wchar_t c : hex)
    {
        if (!iswspace(c))
            cleaned.push_back(c);
    }

    auto is_hex = [](wchar_t c) noexcept
        {
            return (c >= L'0' && c <= L'9') ||
                (c >= L'a' && c <= L'f') ||
                (c >= L'A' && c <= L'F');
        };

    std::wstring h2;
    h2.reserve(cleaned.size());

    for (wchar_t c : cleaned)
    {
        if (is_hex(c))
            h2.push_back(c);
    }

    if (h2.size() & 1)
        h2.pop_back();

    std::vector<unsigned char> out;
    out.reserve(h2.size() / 2);

    for (std::size_t i = 0; i + 1 < h2.size(); i += 2)
    {
        unsigned v = std::stoul(h2.substr(i, 2), nullptr, 16);
        out.push_back(static_cast<unsigned char>(v));
    }

    return out;
}

// Parse offsets in the shell language:
//   "0x1234", "1234", "+0x20", "-16"
// baseOffset is typically the current page offset.
export std::size_t ParseOffset(const std::wstring& s, std::size_t baseOffset)
{
    std::size_t a = 0;
    std::size_t b = s.size();

    while (a < b && iswspace(s[a]))
        ++a;
    while (b > a && iswspace(s[b - 1]))
        --b;

    if (a == b)
        throw std::runtime_error("empty offset");

    std::wstring t = s.substr(a, b - a);

    if (t[0] == L'+' || t[0] == L'-')
    {
        long long delta = std::stoll(t, nullptr, 0);
        long long base = static_cast<long long>(baseOffset);
        long long v = base + delta;
        if (v < 0)
            v = 0;
        return static_cast<std::size_t>(v);
    }

    return static_cast<std::size_t>(std::stoull(t, nullptr, 0));
}

// Simple linear pattern search.
// Returns std::wstring::npos on failure.
export std::size_t FindPattern(std::span<const std::byte> data,
    const std::vector<unsigned char>& pat,
    std::size_t start)
{
    if (pat.empty() || start >= data.size())
        return std::wstring::npos;

    const std::size_t n = data.size();
    const std::size_t m = pat.size();
    if (m > n)
        return std::wstring::npos;

    const unsigned char* p = pat.data();
    const std::byte* d = data.data();

    for (std::size_t i = start; i + m <= n; ++i)
    {
        if (std::memcmp(d + i, p, m) == 0)
            return i;
    }

    return std::wstring::npos;
}
