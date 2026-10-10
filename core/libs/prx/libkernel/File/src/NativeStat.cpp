#include "prx/libkernel/File/include/NativeStat.hpp"
#include "prx/libkernel/File/include/DirectoryDescriptor.hpp"
#include "prx/libc/include/General.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <stdexcept>
#include <string>
#include <system_error>

#ifdef _WIN32
#include "prx/libkernel/File/include/WindowsFileTime.hpp"
#include <io.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <winioctl.h>
struct NativeStat : __stat64 {
    FILE_BASIC_INFO times{};
    BY_HANDLE_FILE_INFORMATION identity{};
    bool hasTimes = false;
    bool hasIdentity = false;
};
struct SymbolicLinkReparseData {
    DWORD tag;
    WORD dataLength;
    WORD reserved;
    WORD substituteNameOffset;
    WORD substituteNameLength;
    WORD printNameOffset;
    WORD printNameLength;
    ULONG flags;
    WCHAR pathBuffer[1];
};
static int ReadHandleInfo(HANDLE handle, NativeStat* st) {
    if (GetFileType(handle) != FILE_TYPE_DISK) return 0;
    if (!GetFileInformationByHandleEx(handle, FileBasicInfo, &st->times, sizeof(st->times)))
        return File::WindowsFileTime::Failure(GetLastError());
    st->hasTimes = true;
    st->hasIdentity = GetFileInformationByHandle(handle, &st->identity) != 0;
    return 0;
}
static std::uint32_t FoldFileIndex(const BY_HANDLE_FILE_INFORMATION& identity) {
    const std::uint32_t folded = identity.nFileIndexLow ^ (identity.nFileIndexHigh * 0x9E3779B1u);
    return folded == 0 ? 1 : folded;
}
static int DoStat(const std::filesystem::path& p, NativeStat* st) {
    if (_wstat64(p.c_str(), st) != 0) return -1;
    const auto handle = CreateFileW(p.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return File::WindowsFileTime::Failure(GetLastError());
    const int result = ReadHandleInfo(handle, st);
    CloseHandle(handle);
    return result;
}
static int DoFstat(int fd, NativeStat* st) {
    if (const auto directory = File::DirectoryDescriptorPath(fd)) return DoStat(*directory, st);
    if (_fstat64(fd, st) != 0) return -1;
    return ReadHandleInfo(reinterpret_cast<HANDLE>(::_get_osfhandle(fd)), st);
}
static bool HasNonDirectoryParent(const std::filesystem::path& path) {
    for (auto parent = path.parent_path(); !parent.empty();) {
        std::error_code error;
        const auto status = std::filesystem::status(parent, error);
        if (!error && std::filesystem::exists(status) && !std::filesystem::is_directory(status)) return true;
        const auto next = parent.parent_path();
        if (next == parent) return false;
        parent = next;
    }
    return false;
}
static int ReadLinkSize(HANDLE handle, NativeStat* st) {
    FILE_ATTRIBUTE_TAG_INFO tag{};
    if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &tag, sizeof(tag)))
        return File::WindowsFileTime::Failure(GetLastError());
    if (tag.ReparseTag != IO_REPARSE_TAG_SYMLINK) return 1;
    std::array<std::uint8_t, MAXIMUM_REPARSE_DATA_BUFFER_SIZE> buffer{};
    DWORD bytes{};
    if (!DeviceIoControl(handle, FSCTL_GET_REPARSE_POINT, nullptr, 0, buffer.data(), static_cast<DWORD>(buffer.size()), &bytes, nullptr))
        return File::WindowsFileTime::Failure(GetLastError());
    constexpr auto reparseHeaderSize = offsetof(SymbolicLinkReparseData, substituteNameOffset);
    constexpr auto pathOffset = offsetof(SymbolicLinkReparseData, pathBuffer);
    if (bytes < reparseHeaderSize) {
        errno = EIO;
        return -1;
    }
    const auto& reparse = *reinterpret_cast<const SymbolicLinkReparseData*>(buffer.data());
    if (reparse.tag != IO_REPARSE_TAG_SYMLINK) {
        errno = EIO;
        return -1;
    }
    if (bytes < pathOffset) {
        errno = EIO;
        return -1;
    }
    if (reparse.dataLength < pathOffset - reparseHeaderSize || reparse.dataLength > bytes - reparseHeaderSize) {
        errno = EIO;
        return -1;
    }
    const auto offset = reparse.printNameLength ? reparse.printNameOffset : reparse.substituteNameOffset;
    const auto length = reparse.printNameLength ? reparse.printNameLength : reparse.substituteNameLength;
    const auto pathLength = reparse.dataLength - (pathOffset - reparseHeaderSize);
    if (offset % sizeof(WCHAR) != 0 || length % sizeof(WCHAR) != 0 ||
        offset > pathLength || length > pathLength - offset) {
        errno = EIO;
        return -1;
    }
    const auto* path = reinterpret_cast<const WCHAR*>(reinterpret_cast<const std::uint8_t*>(reparse.pathBuffer) + offset);
    const int characters = length / sizeof(WCHAR);
    const int utf8Length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path, characters, nullptr, 0, nullptr, nullptr);
    if (utf8Length == 0 && characters != 0) return File::WindowsFileTime::Failure(GetLastError());
    st->st_size = utf8Length;
    return 0;
}
static int DoLstat(const std::filesystem::path& p, NativeStat* st) {
    const auto handle = CreateFileW(p.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        const auto error = GetLastError();
        if (error == ERROR_DIRECTORY || (error == ERROR_PATH_NOT_FOUND && HasNonDirectoryParent(p))) {
            errno = ENOTDIR;
            return -1;
        }
        return File::WindowsFileTime::Failure(error);
    }
    *st = {};
    int result = ReadLinkSize(handle, st);
    if (result > 0) {
        CloseHandle(handle);
        return DoStat(p, st);
    }
    st->st_mode = 0120777;
    if (result == 0) result = ReadHandleInfo(handle, st);
    CloseHandle(handle);
    if (result == 0 && !st->hasIdentity) {
        errno = EIO;
        return -1;
    }
    return result;
}
#else
#include <sys/stat.h>
using NativeStat = struct stat;
static int DoStat(const std::filesystem::path& p, NativeStat* st) {
    return ::stat(p.c_str(), st);
}
static int DoFstat(int fd, NativeStat* st) {
    return ::fstat(fd, st);
}
static int DoLstat(const std::filesystem::path& p, NativeStat* st) {
    return ::lstat(p.c_str(), st);
}
#endif

static void CopyNativeStat(const NativeStat& st, FileStat* sb) {
    *sb = FileStat{};
    sb->st_mode = static_cast<std::uint16_t>(st.st_mode);
    sb->st_size = static_cast<std::int64_t>(st.st_size);
#ifdef _WIN32
    sb->st_dev = static_cast<std::uint32_t>(st.st_dev);
    sb->st_ino = static_cast<std::uint32_t>(st.st_ino);
    sb->st_nlink = static_cast<std::uint16_t>(st.st_nlink);
    sb->st_uid = 0;
    sb->st_gid = 0;
    sb->st_rdev = static_cast<std::uint32_t>(st.st_rdev);
    sb->st_blksize = 512;
    sb->st_blocks = (sb->st_size + 511LL) / 512LL;
    sb->st_atim.tv_sec = static_cast<std::int64_t>(st.st_atime);
    sb->st_atim.tv_nsec = 0;
    sb->st_mtim.tv_sec = static_cast<std::int64_t>(st.st_mtime);
    sb->st_mtim.tv_nsec = 0;
    sb->st_ctim.tv_sec = static_cast<std::int64_t>(st.st_ctime);
    sb->st_ctim.tv_nsec = 0;
    sb->st_birthtim.tv_sec = static_cast<std::int64_t>(st.st_ctime);
    sb->st_birthtim.tv_nsec = 0;
    if (st.hasTimes) {
        sb->st_atim = File::WindowsFileTime::Decode(st.times.LastAccessTime.QuadPart);
        sb->st_mtim = File::WindowsFileTime::Decode(st.times.LastWriteTime.QuadPart);
        sb->st_ctim = File::WindowsFileTime::Decode(st.times.ChangeTime.QuadPart);
        sb->st_birthtim = File::WindowsFileTime::Decode(st.times.CreationTime.QuadPart);
    }
    if (st.hasIdentity) {
        sb->st_dev = st.identity.dwVolumeSerialNumber;
        sb->st_ino = FoldFileIndex(st.identity);
        sb->st_nlink = static_cast<std::uint16_t>(std::min<DWORD>(st.identity.nNumberOfLinks, 0xffff));
    }
#else
    sb->st_dev = static_cast<std::uint32_t>(st.st_dev);
    sb->st_ino = static_cast<std::uint32_t>(st.st_ino);
    sb->st_nlink = static_cast<std::uint16_t>(st.st_nlink);
    sb->st_uid = st.st_uid;
    sb->st_gid = st.st_gid;
    sb->st_rdev = static_cast<std::uint32_t>(st.st_rdev);
    sb->st_blksize = static_cast<std::uint32_t>(st.st_blksize);
    sb->st_blocks = static_cast<std::int64_t>(st.st_blocks);
    sb->st_atim.tv_sec = static_cast<std::int64_t>(st.st_atim.tv_sec);
    sb->st_atim.tv_nsec = static_cast<std::int64_t>(st.st_atim.tv_nsec);
    sb->st_mtim.tv_sec = static_cast<std::int64_t>(st.st_mtim.tv_sec);
    sb->st_mtim.tv_nsec = static_cast<std::int64_t>(st.st_mtim.tv_nsec);
    sb->st_ctim.tv_sec = static_cast<std::int64_t>(st.st_ctim.tv_sec);
    sb->st_ctim.tv_nsec = static_cast<std::int64_t>(st.st_ctim.tv_nsec);
#if defined(__APPLE__)
    sb->st_birthtim.tv_sec = static_cast<std::int64_t>(st.st_birthtimespec.tv_sec);
    sb->st_birthtim.tv_nsec = static_cast<std::int64_t>(st.st_birthtimespec.tv_nsec);
#elif defined(__linux__)
    sb->st_birthtim = sb->st_ctim;
#else
    sb->st_birthtim.tv_sec = static_cast<std::int64_t>(st.st_birthtim.tv_sec);
    sb->st_birthtim.tv_nsec = static_cast<std::int64_t>(st.st_birthtim.tv_nsec);
#endif
#endif
}

namespace File {

void FillFileStat(const std::filesystem::path& nativePath, FileStat* sb) {
    NativeStat st{};
    if (DoStat(nativePath, &st) != 0) {
        throw std::runtime_error(std::string("FillFileStat: stat failed for ") + nativePath.string());
    }
    CopyNativeStat(st, sb);
}

void FillFileStat(int nativeDescriptor, FileStat* sb) {
    NativeStat st{};
    if (DoFstat(nativeDescriptor, &st) != 0) {
        throw std::runtime_error(std::string("FillFileStat: fstat failed for fd ") + std::to_string(nativeDescriptor));
    }
    CopyNativeStat(st, sb);
}

bool FillFileStatFromDescriptor(int fd, FileStat* sb) {
    NativeStat st{};
    if (DoFstat(fd, &st) != 0) return false;
    CopyNativeStat(st, sb);
    return true;
}

bool FillLinkStat(const std::filesystem::path& nativePath, FileStat* sb) {
    NativeStat st{};
    if (DoLstat(nativePath, &st) != 0) return false;
    CopyNativeStat(st, sb);
    return true;
}

}
