# ALDI v0.1.0 — The Almond Disassembler

ALDI (the Almond Disassembler) is a Windows-first reverse engineering utility built with modern C++ and Win32. It combines a hex viewer, disassembler, and command-driven workflow to quickly inspect binaries and apply patches without leaving a lightweight desktop UI.

## Current capabilities
- **Hex viewer:** Page through the loaded binary with quick Previous/Next navigation and scroll-wheel support.
- **Pattern search:** Search for byte signatures and iterate through hits with `find` / `findnext` commands.
- **Disassembler (Zydis 4.1.1):** Decode regions of code for inspection using the bundled Zydis backend.
- **VFT inspector:** Interpret regions as virtual function tables to map out class layouts.
- **Patching and templates:** Apply direct file patches, bookmark offsets, and save reusable patch templates.

## Usage
1. Build or download the ALDI binary on Windows (see [Build instructions](#build-instructions)).
2. Launch the application and click **Open…** to select the target executable or binary blob.
3. Navigate the file with the **Prev/Next** buttons or your mouse wheel.
4. Type commands into the **Command** box and press **Enter**. Common commands include:
   - `find <hex>` / `findnext` — locate the next byte pattern occurrence.
   - `disasm <off> <size>` — disassemble a region using Zydis.
   - `vft <off> <count>` — render a section as 8-byte RVAs for VFT inspection.
   - `patch <off> <hex>` — write a patch at the given offset.
   - `label <off> <name>` — bookmark an offset for quick reference.
   - `dump <off> <size>` — emit a hex dump of a range.
5. Results render directly in the output pane; commands that change the view refresh the current page automatically.

## Build instructions
ALDI targets Windows and depends on [Zydis](https://github.com/zyantific/zydis) for disassembly. The repository includes a `vcpkg.json` manifest to simplify dependency setup.

### Prerequisites
- Windows with Visual Studio 2022 (C++ toolset) or MSBuild available in the Developer Command Prompt.
- [vcpkg](https://github.com/microsoft/vcpkg) installed and on your PATH.

### Steps
1. Restore dependencies via vcpkg:
   ```powershell
   cd ALDI
   vcpkg install --triplet x64-windows
   ```
   The manifest will pull Zydis 4.1.1 automatically.
2. Open `ALDI.slnx` in Visual Studio and select the **x64** configuration.
3. Build the **Release** (or **Debug**) target. The post-build artifacts can be launched directly.

> Tip: If you use a custom vcpkg installation path, set the `VCPKG_ROOT` environment variable or integrate vcpkg with Visual Studio (`vcpkg integrate install`) so the solution can locate the installed ports.

## Version & changelog
- **v0.1.0** — Initial documented release with hex viewer, pattern search, disassembler (Zydis 4.1.1), VFT inspector, and patch/template commands.
