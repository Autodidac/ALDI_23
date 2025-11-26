export module mod_disasm;

import <string>;
import <sstream>;
import <iomanip>;
import <cstddef>;
import <cstdint>;
import <vector>;
import <span>;
import <cstring>;

// Zydis include via vcpkg
import "Zycore/Types.h";
import "Zydis/Zydis.h";

// -----------------------------------------------------------------------------
// Minimal PE Layout helpers
// -----------------------------------------------------------------------------

struct PELayout
{
    bool        valid{};
    bool        is64{};
    std::uint64_t imageBase{};
    std::uint32_t textRVA{};
    std::uint32_t textRaw{};
    std::uint32_t textRawSize{};
};

static bool ReadU16(std::span<const std::byte> d, std::size_t off, std::uint16_t& out)
{
    if (off + 2 > d.size()) return false;
    auto p = reinterpret_cast<const unsigned char*>(d.data() + off);
    out = p[0] | (p[1] << 8);
    return true;
}

static bool ReadU32(std::span<const std::byte> d, std::size_t off, std::uint32_t& out)
{
    if (off + 4 > d.size()) return false;
    auto p = reinterpret_cast<const unsigned char*>(d.data() + off);
    out = p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
    return true;
}

static bool ReadU64(std::span<const std::byte> d, std::size_t off, std::uint64_t& out)
{
    if (off + 8 > d.size()) return false;
    auto p = reinterpret_cast<const unsigned char*>(d.data() + off);
    out =
        (std::uint64_t)p[0] |
        ((std::uint64_t)p[1] << 8) |
        ((std::uint64_t)p[2] << 16) |
        ((std::uint64_t)p[3] << 24) |
        ((std::uint64_t)p[4] << 32) |
        ((std::uint64_t)p[5] << 40) |
        ((std::uint64_t)p[6] << 48) |
        ((std::uint64_t)p[7] << 56);
    return true;
}

static PELayout AnalyzePE(std::span<const std::byte> data)
{
    PELayout L{};

    if (data.size() < 0x200) return L;

    // DOS
    if ((char)data[0] != 'M' || (char)data[1] != 'Z')
        return L;

    std::uint32_t peoff{};
    if (!ReadU32(data, 0x3C, peoff)) return L;

    if (peoff + 0xF8 > data.size()) return L;
    if ((char)data[peoff] != 'P' ||
        (char)data[peoff + 1] != 'E')
        return L;

    // FILE HEADER
    std::uint16_t sections{};
    std::uint16_t optSize{};
    ReadU16(data, peoff + 6, sections);
    ReadU16(data, peoff + 20, optSize);

    // OPTIONAL HEADER
    std::uint16_t magic{};
    ReadU16(data, peoff + 24, magic);
    L.is64 = (magic == 0x20B);

    if (L.is64)
        ReadU64(data, peoff + 24 + 24, L.imageBase);
    else
    {
        std::uint32_t ib32{};
        ReadU32(data, peoff + 24 + 28, ib32);
        L.imageBase = ib32;
    }

    // SECTION TABLE
    std::size_t sect = peoff + 24 + optSize;
    for (int i = 0; i < sections; i++)
    {
        const std::byte* s = data.data() + sect + i * 40;

        char name[9]{};
        for (int j = 0; j < 8; j++)
            name[j] = (char)s[j];

        if (std::string_view(name).starts_with(".text"))
        {
            ReadU32(data, sect + i * 40 + 12, L.textRVA);
            ReadU32(data, sect + i * 40 + 20, L.textRaw);
            ReadU32(data, sect + i * 40 + 16, L.textRawSize);

            L.valid = true;
            break;
        }
    }

    return L;
}

static bool FileFromRVA(const PELayout& L,
    std::uint32_t rva,
    std::size_t& out)
{
    if (!L.valid) return false;
    if (rva < L.textRVA) return false;
    std::uint32_t delta = rva - L.textRVA;
    if (delta >= L.textRawSize) return false;
    out = L.textRaw + delta;
    return true;
}

// ---------------------------------------------------------------------------
// Disassemble code region using Zydis 4.1.1 with PE-aware addressing
// ---------------------------------------------------------------------------
export std::wstring DisasmRegion(
    std::span<const std::byte> data,
    std::size_t fileOffset,
    std::size_t size,
    std::uint64_t baseAddress)
{
    const std::size_t max = std::min(fileOffset + size, data.size());
    if (fileOffset >= data.size() || max <= fileOffset)
        return L"(empty)\r\n";

    std::wstringstream out;

    const PELayout PE = AnalyzePE(data);

    if (!PE.valid)
    {
        out << L"(Not a PE file — linear disasm)\r\n\r\n";
    }

    // Map offset→RVA (for real addresses)
    std::uint32_t rva{};
    if (PE.valid)
    {
        if (fileOffset < PE.textRaw ||
            fileOffset >= PE.textRaw + PE.textRawSize)
        {
            out << L"(Offset 0x" << std::hex << fileOffset
                << L" is not in .text)\r\n";
            return out.str();
        }
        rva = static_cast<std::uint32_t>(fileOffset - PE.textRaw + PE.textRVA);
    }
    else
    {
        rva = static_cast<std::uint32_t>(fileOffset);
    }

    ZydisDecoder decoder{};
    if (ZYAN_FAILED(ZydisDecoderInit(
        &decoder,
        ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_STACK_WIDTH_64)))
    {
        return L"Decoder init failed\r\n";
    }

    ZydisFormatter fmt{};
    if (ZYAN_FAILED(ZydisFormatterInit(
        &fmt,
        ZYDIS_FORMATTER_STYLE_INTEL)))
    {
        return L"Formatter init failed\r\n";
    }

    ZyanUSize cur = 0;
    ZyanUSize avail = static_cast<ZyanUSize>(max - fileOffset);

    while (cur < avail)
    {
        ZydisDecodedInstruction inst{};
        ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT]{};

        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
            &decoder,
            data.data() + fileOffset + cur,
            avail - cur,
            &inst,
            ops)))
        {
            break;
        }

        char buf[256]{};

        ZyanU64 runtime = PE.valid ?
            (PE.imageBase + rva) :
            (baseAddress + rva);

        ZydisFormatterFormatInstruction(
            &fmt,
            &inst,
            ops,
            inst.operand_count_visible,
            buf,
            sizeof(buf),
            runtime,
            nullptr);

        std::wstring ws;
        for (char c : std::string(buf))
        {
            if (!c) break;
            ws.push_back(static_cast<unsigned char>(c));
        }

        out << L"0x" << std::hex << runtime << L"  " << ws << L"\r\n";

        cur += inst.length;
        rva += inst.length;
    }

    return out.str();
}

// ---------------------------------------------------------------------------
// VFT: virtual-function-table style RVA disassembly
// ---------------------------------------------------------------------------
export std::wstring DisasmVFT(
    std::span<const std::byte> data,
    std::size_t offset,
    std::size_t count,
    std::uint64_t baseAddress)
{
    std::wstringstream out;

    const PELayout PE = AnalyzePE(data);
    const std::size_t ptrSize = PE.is64 ? 8 : 4;

    out << L"VFT @ 0x" << std::hex << offset << L"\r\n\r\n";

    if (offset + count * ptrSize > data.size())
    {
        out << L"(out of range)\r\n";
        return out.str();
    }

    for (std::size_t i = 0; i < count; i++)
    {
        std::size_t off = offset + i * ptrSize;
        if (off + ptrSize > data.size())
        {
            out << L"[#" << i << L"] <out of range>\r\n";
            continue;
        }

        std::uint64_t va{};
        std::memcpy(&va, data.data() + off, ptrSize);

        out << L"[#" << i << L"] 0x" << std::hex << va << L"\r\n";

        // Map VA→RVA→file offset
        std::uint32_t rva = static_cast<std::uint32_t>(va - PE.imageBase);
        std::size_t codeOff{};

        if (!PE.valid || !FileFromRVA(PE, rva, codeOff))
        {
            out << L"   (not in .text)\r\n\r\n";
            continue;
        }

        out << DisasmRegion(data, codeOff, 64, baseAddress) << L"\r\n";
    }

    return out.str();
}
