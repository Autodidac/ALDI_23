export module mod_disasm;

import <string>;
import <sstream>;
import <iomanip>;
import <cstddef>;
import <cstdint>;
import <vector>;
import <span>;

// Zydis 4.1.1 (as installed through vcpkg include folders)
import "Zycore/Types.h";
import "Zydis/Zydis.h";

// ---------------------------------------------------------------------------
// Disassemble code region using Zydis 4.1.1
// ---------------------------------------------------------------------------
export std::wstring DisasmRegion(
    std::span<const std::byte> data,
    std::size_t offset,
    std::size_t size,
    std::uint64_t baseAddress
)
{
    const std::size_t end = offset + size;
    if (offset >= data.size() || end <= offset)
        return L"(empty)\r\n";

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

    std::wstringstream out;
    out << L"Disasm @ offset 0x"
        << std::hex << offset << L"\r\n\r\n";

    ZyanUSize cur = 0;
    ZyanUSize avail = static_cast<ZyanUSize>(std::min(end, data.size()) - offset);

    while (cur < avail)
    {
        ZydisDecodedInstruction inst{};
        ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT]{};

        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
            &decoder,
            data.data() + offset + cur,
            avail - cur,
            &inst,
            ops)))
        {
            break;
        }

        char buf[256]{};
        ZyanU64 addr = baseAddress + offset + cur;

        ZydisFormatterFormatInstruction(
            &fmt,
            &inst,
            ops,
            inst.operand_count_visible,
            buf,
            sizeof(buf),
            addr,
            nullptr);

        std::wstring ws;
        for (char c : std::string(buf))
        {
            if (!c) break;
            ws.push_back(static_cast<unsigned char>(c));
        }

        out << L"0x" << std::hex << addr << L"  " << ws << L"\r\n";
        cur += inst.length;
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
    std::uint64_t baseAddress
)
{
    std::wstringstream out;

    out << L"VFT @ file offset 0x"
        << std::hex << offset
        << L", count "
        << std::dec << count << L"\r\n\r\n";

    if (offset + count * 8 > data.size())
    {
        out << L"(out of range)\r\n";
        return out.str();
    }

    for (std::size_t i = 0; i < count; ++i)
    {
        std::size_t off = offset + i * 8;
        std::uint64_t rva{};
        std::memcpy(&rva, data.data() + off, 8);

        out << L"[#" << i << L"] RVA 0x" << std::hex << rva;

        if (rva < data.size())
        {
            out << L" (file off 0x" << rva << L")\r\n";
            out << DisasmRegion(
                data,
                static_cast<std::size_t>(rva),
                64,
                baseAddress + rva);
            out << L"\r\n";
        }
        else
        {
            out << L" (out of file range)\r\n";
        }
    }

    return out.str();
}
