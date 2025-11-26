<<<<<<< HEAD
<<<<<<< HEAD
﻿export module mod_pe_utils;
=======
export module mod_pe_utils;
>>>>>>> origin/main
=======
export module mod_pe_utils;
>>>>>>> origin/main

import <cstdint>;
import <cstddef>;
import <string>;
<<<<<<< HEAD
<<<<<<< HEAD
import <vector>;
=======
>>>>>>> origin/main
=======
>>>>>>> origin/main
import <span>;
import <stdexcept>;

//
<<<<<<< HEAD
<<<<<<< HEAD
// Compact, safe PE parser for 64-bit Windows PE files.
// Supports:
//
//  * DOS header
//  * NT header
//  * Optional header (PE32+ minimal fields)
//  * Section headers
//  * RVA ↔ file offset translation
//  * .text lookup
//

export namespace pe
{
    // ------------------------------------------------------------
    // Raw PE tables (minimal)
    // ------------------------------------------------------------

    struct DosHeader
    {
        std::uint16_t e_magic;
=======
=======
>>>>>>> origin/main
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
<<<<<<< HEAD
>>>>>>> origin/main
=======
>>>>>>> origin/main
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
<<<<<<< HEAD
<<<<<<< HEAD
        std::uint32_t e_lfanew;
    };

    struct FileHeader
    {
        std::uint32_t signature; // "PE\0\0"
        std::uint16_t machine;
        std::uint16_t sectionCount;
        std::uint32_t timeStamp;
        std::uint32_t ptrSymbols;
        std::uint32_t symbolCount;
        std::uint16_t optHeaderSize;
        std::uint16_t characteristics;
    };

    struct OptionalHeader64
    {
        std::uint16_t magic;     // 0x20B
=======
=======
>>>>>>> origin/main
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
<<<<<<< HEAD
>>>>>>> origin/main
=======
>>>>>>> origin/main
        std::uint8_t  linkerMajor;
        std::uint8_t  linkerMinor;
        std::uint32_t sizeCode;
        std::uint32_t sizeInitData;
        std::uint32_t sizeUninitData;
<<<<<<< HEAD
<<<<<<< HEAD
        std::uint32_t entryRVA;
        std::uint64_t imageBase;

        // We stop here—this is enough for disassembly.
    };

    struct Section
    {
        std::string     name;
        std::uint32_t   virtualSize;
        std::uint32_t   virtualAddress;  // RVA
        std::uint32_t   rawSize;
        std::uint32_t   rawOffset;
    };

    struct Layout
    {
        bool valid{};
        std::uint64_t imageBase{};
        std::uint32_t entryRVA{};
        std::vector<Section> sections;

        // Cached .text references
        const Section* text{};
    };

    // ------------------------------------------------------------
    // Read helpers (module-internal, not exported)
    // ------------------------------------------------------------
    template<typename T>
    bool read(std::span<const std::byte> d, std::size_t off, T& out)
    {
        if (off + sizeof(T) > d.size()) return false;
        std::memcpy(&out, d.data() + off, sizeof(T));
        return true;
    }

    // ------------------------------------------------------------
    // Parse entire PE layout
    // ------------------------------------------------------------
    export inline Layout analyze(std::span<const std::byte> data)
    {
        Layout L{};

        if (data.size() < sizeof(DosHeader))
            return L;

        DosHeader dos{};
        if (!read(data, 0, dos)) return L;
        if (dos.e_magic != 0x5A4D) return L; // MZ

        FileHeader file{};
        if (!read(data, dos.e_lfanew, file)) return L;
        if (file.signature != 0x00004550) return L; // PE00

        OptionalHeader64 opt{};
        if (!read(data, dos.e_lfanew + sizeof(FileHeader), opt)) return L;
        if (opt.magic != 0x20B) return L; // Only PE32+

        L.valid = true;
        L.imageBase = opt.imageBase;
        L.entryRVA = opt.entryRVA;

        // Parse sections
        std::size_t sectStart = dos.e_lfanew + sizeof(FileHeader) + file.optHeaderSize;
        L.sections.reserve(file.sectionCount);

        for (int i = 0; i < file.sectionCount; i++)
        {
            std::size_t off = sectStart + i * 40; // IMAGE_SECTION_HEADER size

            char name[9]{};
            std::memcpy(name, data.data() + off, 8);

            std::uint32_t vs{}, va{}, rs{}, ro{};
            read(data, off + 8, vs);
            read(data, off + 12, va);
            read(data, off + 16, rs);
            read(data, off + 20, ro);

            Section s{
                name,
                vs,
                va,
                rs,
                ro
            };

            L.sections.push_back(s);

            if (!L.text && s.name.starts_with(".text"))
                L.text = &L.sections.back();
        }

        return L;
    }

    // ------------------------------------------------------------
    // RVA → file offset
    // ------------------------------------------------------------
    export inline bool rva_to_file(const Layout& L, std::uint32_t rva, std::size_t& out)
    {
        if (!L.valid) return false;

        for (auto& s : L.sections)
        {
            if (rva >= s.virtualAddress &&
                rva < s.virtualAddress + s.virtualSize)
            {
                out = (rva - s.virtualAddress) + s.rawOffset;
                return true;
            }
        }
        return false;
    }

    // ------------------------------------------------------------
    // Format string for the UI
    // ------------------------------------------------------------
    export inline std::wstring describe(const Layout& L)
    {
        if (!L.valid)
            return L"Not a PE file.";

        std::wstring s;
        s += L"PE32+ detected\n";
        s += L"ImageBase: 0x" + std::to_wstring(L.imageBase) + L"\n";
        s += L"Entry RVA: 0x" + std::to_wstring(L.entryRVA) + L"\n";
        s += L"Sections:\n";

        for (auto& sec : L.sections)
        {
            s += L"  " + std::wstring(sec.name.begin(), sec.name.end()) +
                L" RVA=0x" + std::to_wstring(sec.virtualAddress) +
                L" Raw=0x" + std::to_wstring(sec.rawOffset) +
                L" Size=" + std::to_wstring(sec.rawSize) + L"\n";
        }

        return s;
=======
=======
>>>>>>> origin/main
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
<<<<<<< HEAD
>>>>>>> origin/main
=======
>>>>>>> origin/main
    }
}
