export module mod_hex;

import <string>;
import <span>;
import <cstddef>;
import <cstdint>;
import <sstream>;
import <iomanip>;
import <algorithm>;

export constexpr std::size_t kPageSize = 4096;

template<typename T>
static constexpr T mmin(T a, T b) noexcept
{
    return (std::min)(a, b);
}

// Render a hex + ASCII view of a slice of bytes.
export std::wstring HexPage(std::span<const std::byte> data,
    std::size_t off,
    std::size_t cnt)
{
    const std::size_t end = mmin(off + cnt, data.size());
    const std::size_t n = (end > off) ? (end - off) : 0;

    std::wstringstream out;

    for (std::size_t i = 0; i < n; i += 16)
    {
        const std::size_t addr = off + i;

        out << std::hex << std::setw(8) << std::setfill(L'0')
            << addr << L"  ";

        for (std::size_t j = 0; j < 16; ++j)
        {
            if (i + j < n)
            {
                unsigned v = std::to_integer<unsigned char>(data[off + i + j]);
                out << std::setw(2) << v << L" ";
            }
            else
            {
                out << L"   ";
            }
        }

        out << L" ";

        for (std::size_t j = 0; j < 16 && (i + j) < n; ++j)
        {
            unsigned char c = std::to_integer<unsigned char>(data[off + i + j]);
            out << ((c >= 32 && c < 127) ? wchar_t(c) : L'.');
        }

        out << L"\r\n";
    }

    return out.str();
}

export std::wstring HexDumpRegion(std::span<const std::byte> data,
    std::size_t off,
    std::size_t size)
{
    const std::size_t end = mmin(off + size, data.size());
    const std::size_t n = (end > off) ? (end - off) : 0;

    std::wstringstream out;
    out << std::uppercase
        << L"Dump @ 0x"
        << std::hex << off
        << L", size "
        << std::dec << n
        << L"\r\n\r\n";

    out << HexPage(data, off, n);
    return out.str();
}
