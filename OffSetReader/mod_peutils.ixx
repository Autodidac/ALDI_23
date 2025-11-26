export module mod_pe_utils;

import <cstdint>;
import <cstddef>;
import <string>;
import <span>;
import <stdexcept>;

//
// Tiny PE helper module.
// Only minimal offsets and existence checks, not a full parser.
//
export namespace pe
{
    // ------------------------------------------------------------
    // DOS Header
    // ------------------------------------------------------------
    struct DosHeader
    {
        std::uint16_t e_magic;      // 'MZ'
        std::uint16_t e_cblp;
        std::uint16_t e_cp;
        std::uint16_t e_crlc;
        std::uint16_t e_cparhdr;
        std::uint16_t e_minalloc;
        std::uint16_t e_maxalloc;
        std::uint16_t e_ss;
        std::uint16_t e_sp;
        std::uint16_t e_csum;
        std::uint16_t e_ip;
        std::uint16_t e_cs;
        std::uint16_t e_lfarlc;
        std::uint16_t e_ovno;
        std::uint16_t e_res[4];
        std::uint16_t e_oemid;
        std::uint16_t e_oeminfo;
        std::uint16_t e_res2[10];
        std::uint32_t e_lfanew;     // PE header offset
    };

    // ------------------------------------------------------------
    // NT Headers (bare minimum)
    // ------------------------------------------------------------
    struct NtHeader
    {
        std::uint32_t sig;          // 'PE\0\0'
        std::uint16_t machine;
        std::uint16_t numberOfSections;
        std::uint32_t timeDateStamp;
        std::uint32_t ptrSymbolTable;
        std::uint32_t numSymbols;
        std::uint16_t sizeOfOptionalHeader;
        std::uint16_t characteristics;
    };

    // Minimal optional header (only magic + entry)
    struct OptionalHeader
    {
        std::uint16_t magic;        // PE32 (0x10B) or PE64 (0x20B)
        std::uint8_t  linkerMajor;
        std::uint8_t  linkerMinor;
        std::uint32_t sizeCode;
        std::uint32_t sizeInitData;
        std::uint32_t sizeUninitData;
        std::uint32_t entryPointRVA;
        // We intentionally stop here; we only need EP.
    };

    // ------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------
    constexpr bool has_mz_header(std::span<const std::byte> data) noexcept
    {
        if (data.size() < sizeof(DosHeader)) return false;
        auto dos = reinterpret_cast<const DosHeader*>(data.data());
        return dos->e_magic == 0x5A4D; // "MZ"
    }

    constexpr bool has_pe_header(std::span<const std::byte> data) noexcept
    {
        if (!has_mz_header(data)) return false;

        auto dos = reinterpret_cast<const DosHeader*>(data.data());
        if (dos->e_lfanew + sizeof(NtHeader) > data.size()) return false;

        auto nt = reinterpret_cast<const NtHeader*>(
            reinterpret_cast<const std::byte*>(data.data()) + dos->e_lfanew
            );

        return nt->sig == 0x00004550; // "PE\0\0"
    }

    // Get entry point RVA (not VA)
    inline std::uint32_t get_entry_rva(std::span<const std::byte> data)
    {
        if (!has_pe_header(data))
            throw std::runtime_error("Invalid PE file: missing PE header");

        auto dos = reinterpret_cast<const DosHeader*>(data.data());
        auto base = reinterpret_cast<const std::byte*>(data.data()) + dos->e_lfanew;

        auto nt = reinterpret_cast<const NtHeader*>(base);
        auto opt = reinterpret_cast<const OptionalHeader*>(base + sizeof(NtHeader));

        return opt->entryPointRVA;
    }

    // Returns formatted summary for UI text output
    inline std::wstring describe_pe(std::span<const std::byte> data)
    {
        if (!has_pe_header(data))
            return L"Not a PE file.";

        auto dos = reinterpret_cast<const DosHeader*>(data.data());
        auto base = reinterpret_cast<const std::byte*>(data.data()) + dos->e_lfanew;
        auto nt = reinterpret_cast<const NtHeader*>(base);
        auto opt = reinterpret_cast<const OptionalHeader*>(base + sizeof(NtHeader));

        std::wstring out;
        out += L"PE Header detected\n";
        out += L"Sections: " + std::to_wstring(nt->numberOfSections) + L"\n";
        out += L"Entry RVA: 0x" + std::to_wstring(opt->entryPointRVA) + L"\n";

        return out;
    }
}
