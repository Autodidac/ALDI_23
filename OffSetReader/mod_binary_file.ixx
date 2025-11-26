export module mod_binary_file;

import <string>;
import <vector>;
import <span>;
import <cstddef>;
import <cstdint>;
import <fstream>;
import <cstring>;

export class BinaryFile
{
public:
    BinaryFile() = default;

    bool load(const std::wstring& path)
    {
        clear();

#ifdef _WIN32
        std::ifstream f(path, std::ios::binary);
#else
        // Convert UTF-16 → UTF-8 on non-Win platforms
        std::string utf8(path.begin(), path.end());
        std::ifstream f(utf8, std::ios::binary);
#endif

        if (!f)
            return false;

        f.seekg(0, std::ios::end);
        auto pos = f.tellg();
        if (pos < 0)
            return false;

        m_size = static_cast<std::size_t>(pos);
        m_buffer.resize(m_size);

        f.seekg(0, std::ios::beg);
        if (!f.read(reinterpret_cast<char*>(m_buffer.data()),
            static_cast<std::streamsize>(m_size)))
        {
            clear();
            return false;
        }

        m_path = path;
        return true;
    }

    bool patch(std::size_t offset, const void* data, std::size_t len)
    {
        if (!data || offset + len > m_size || m_path.empty())
            return false;

        std::memcpy(m_buffer.data() + offset, data, len);

#ifdef _WIN32
        std::fstream f(m_path, std::ios::binary | std::ios::in | std::ios::out);
#else
        std::string utf8(m_path.begin(), m_path.end());
        std::fstream f(utf8, std::ios::binary | std::ios::in | std::ios::out);
#endif

        if (!f)
            return false;

        f.seekp(static_cast<std::streamoff>(offset));
        f.write(reinterpret_cast<const char*>(data),
            static_cast<std::streamsize>(len));

        return f.good();
    }

    [[nodiscard]] std::span<const std::byte> bytes() const noexcept
    {
        return m_buffer;
    }

    [[nodiscard]] std::size_t size() const noexcept
    {
        return m_size;
    }

    [[nodiscard]] const std::wstring& path() const noexcept
    {
        return m_path;
    }

    void clear() noexcept
    {
        m_path.clear();
        m_buffer.clear();
        m_buffer.shrink_to_fit();
        m_size = 0;
    }

private:
    std::wstring           m_path{};
    std::vector<std::byte> m_buffer{};
    std::size_t            m_size{};
};

// ------------------------------------------------------------
// Global instance + exports
// ------------------------------------------------------------

static BinaryFile g_file;

export BinaryFile& GetBinaryFile()
{
    return g_file;
}

export bool CoreLoadFile(const std::wstring& path)
{
    return g_file.load(path);
}

export bool CorePatchFile(std::size_t offset,
    const std::vector<unsigned char>& bytes)
{
    if (bytes.empty())
        return false;

    return g_file.patch(offset, bytes.data(), bytes.size());
}

export std::span<const std::byte> CoreBytes() noexcept
{
    return g_file.bytes();
}

export std::size_t CoreSize() noexcept
{
    return g_file.size();
}

export const std::wstring& CorePath() noexcept
{
    return g_file.path();
}
