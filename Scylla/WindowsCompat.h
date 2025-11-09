/*
 * Windows Compatibility Header for Cross-Platform Builds
 *
 * This header provides Windows types and definitions needed for PE file analysis
 * on non-Windows platforms (Linux, macOS).
 */

#pragma once

#ifdef _WIN32
    // On Windows, just include windows.h
    #include <windows.h>
#else
    // On non-Windows platforms, provide necessary Windows type definitions
    #include <cstdint>
    #include <cstring>
    #include <cwchar>
    #include <cstdlib>
    #include <cstdarg>
    #include <cstdio>

    // Basic Windows types
    typedef uint8_t BYTE;
    typedef uint16_t WORD;
    typedef uint32_t DWORD;
    typedef int32_t LONG;
    typedef int64_t LONGLONG;
    typedef uint64_t QWORD;
    typedef uint64_t DWORD64;
    typedef uint64_t ULONGLONG;
    typedef int32_t NTSTATUS;
    typedef int BOOL;
    typedef unsigned long ULONG;
    typedef unsigned short USHORT;
    typedef unsigned char UCHAR;
    typedef char CHAR;
    typedef wchar_t WCHAR;
    typedef void* PVOID;
    typedef void* LPVOID;
    typedef const void* LPCVOID;
    typedef char* LPSTR;
    typedef const char* LPCSTR;
    typedef wchar_t* LPWSTR;
    typedef wchar_t* PWSTR;
    typedef const wchar_t* LPCWSTR;
    typedef size_t SIZE_T;
    typedef void* HANDLE;
    typedef HANDLE* PHANDLE;
    typedef HANDLE HMODULE;
    typedef HANDLE HINSTANCE;
    typedef HANDLE HWND;
    typedef ULONG* PULONG;
    typedef uint8_t BOOLEAN;
    typedef DWORD ACCESS_MASK;
    typedef SIZE_T* PSIZE_T;
    typedef BOOL* PBOOL;
    typedef DWORD* LPDWORD;
    typedef LONG* PLONG;
    typedef void* (*LPTHREAD_START_ROUTINE)(void*);

    // Calling conventions (no-op on non-Windows)
    #define __cdecl
    #define WINAPI

    // Large integer structure
    typedef union _LARGE_INTEGER {
        struct {
            DWORD LowPart;
            LONG  HighPart;
        };
        int64_t QuadPart;
    } LARGE_INTEGER, *PLARGE_INTEGER;

    // List entry structure
    typedef struct _LIST_ENTRY {
        struct _LIST_ENTRY *Flink;
        struct _LIST_ENTRY *Blink;
    } LIST_ENTRY, *PLIST_ENTRY;

    // Pointer types
    #ifdef __LP64__
        typedef uint64_t DWORD_PTR;
        typedef int64_t LONG_PTR;
        typedef uint64_t ULONG_PTR;
    #else
        typedef uint32_t DWORD_PTR;
        typedef int32_t LONG_PTR;
        typedef uint32_t ULONG_PTR;
    #endif

    typedef ULONG_PTR SIZE_T;
    typedef LONG_PTR SSIZE_T;

    // Boolean values
    #ifndef TRUE
        #define TRUE 1
    #endif
    #ifndef FALSE
        #define FALSE 0
    #endif

    // Common macros
    #ifndef MAX_PATH
        #define MAX_PATH 260
    #endif

    #ifndef NOMINMAX
        #define NOMINMAX
    #endif

    // Common Windows macros
    #define ZeroMemory(Destination,Length) memset((Destination),0,(Length))
    #define CopyMemory(Destination,Source,Length) memcpy((Destination),(Source),(Length))
    #define TEXT(x) L##x

    // Printf format macros for cross-platform pointer printing
    #ifdef __LP64__
        // 64-bit
        #define PRINTF_DWORD_PTR_FULL_S "%016lX"
        #define PRINTF_DWORD_PTR_HALF_S "%08lX"
        #define PRINTF_DWORD_PTR_S "%lX"
        #define PRINTF_DWORD_PTR_FULL L"%016lX"
        #define PRINTF_DWORD_PTR_HALF L"%08lX"
        #define PRINTF_DWORD_PTR L"%lX"
    #else
        // 32-bit
        #define PRINTF_DWORD_PTR_FULL_S "%08X"
        #define PRINTF_DWORD_PTR_HALF_S "%08X"
        #define PRINTF_DWORD_PTR_S "%X"
        #define PRINTF_DWORD_PTR_FULL L"%08X"
        #define PRINTF_DWORD_PTR_HALF L"%08X"
        #define PRINTF_DWORD_PTR L"%X"
    #endif

    // Processor architecture constants
    #define PROCESSOR_ARCHITECTURE_INTEL   0
    #define PROCESSOR_ARCHITECTURE_AMD64   9
    #define PROCESSOR_ARCHITECTURE_ARM     5
    #define PROCESSOR_ARCHITECTURE_ARM64   12

    // System information structure
    typedef struct _SYSTEM_INFO {
        union {
            DWORD dwOemId;
            struct {
                WORD wProcessorArchitecture;
                WORD wReserved;
            };
        };
        DWORD dwPageSize;
        LPVOID lpMinimumApplicationAddress;
        LPVOID lpMaximumApplicationAddress;
        DWORD_PTR dwActiveProcessorMask;
        DWORD dwNumberOfProcessors;
        DWORD dwProcessorType;
        DWORD dwAllocationGranularity;
        WORD wProcessorLevel;
        WORD wProcessorRevision;
    } SYSTEM_INFO, *LPSYSTEM_INFO;

    // OS Version structures
    typedef struct _OSVERSIONINFOA {
        DWORD dwOSVersionInfoSize;
        DWORD dwMajorVersion;
        DWORD dwMinorVersion;
        DWORD dwBuildNumber;
        DWORD dwPlatformId;
        CHAR  szCSDVersion[128];
    } OSVERSIONINFOA, *POSVERSIONINFOA, *LPOSVERSIONINFOA;

    typedef struct _OSVERSIONINFOW {
        DWORD dwOSVersionInfoSize;
        DWORD dwMajorVersion;
        DWORD dwMinorVersion;
        DWORD dwBuildNumber;
        DWORD dwPlatformId;
        WCHAR szCSDVersion[128];
    } OSVERSIONINFOW, *POSVERSIONINFOW, *LPOSVERSIONINFOW;

    typedef struct _OSVERSIONINFOEXA {
        DWORD dwOSVersionInfoSize;
        DWORD dwMajorVersion;
        DWORD dwMinorVersion;
        DWORD dwBuildNumber;
        DWORD dwPlatformId;
        CHAR  szCSDVersion[128];
        WORD  wServicePackMajor;
        WORD  wServicePackMinor;
        WORD  wSuiteMask;
        BYTE  wProductType;
        BYTE  wReserved;
    } OSVERSIONINFOEXA, *POSVERSIONINFOEXA, *LPOSVERSIONINFOEXA;

    typedef struct _OSVERSIONINFOEXW {
        DWORD dwOSVersionInfoSize;
        DWORD dwMajorVersion;
        DWORD dwMinorVersion;
        DWORD dwBuildNumber;
        DWORD dwPlatformId;
        WCHAR szCSDVersion[128];
        WORD  wServicePackMajor;
        WORD  wServicePackMinor;
        WORD  wSuiteMask;
        BYTE  wProductType;
        BYTE  wReserved;
    } OSVERSIONINFOEXW, *POSVERSIONINFOEXW, *LPOSVERSIONINFOEXW;

    #ifdef UNICODE
        typedef OSVERSIONINFOW OSVERSIONINFO;
        typedef OSVERSIONINFOEXW OSVERSIONINFOEX;
    #else
        typedef OSVERSIONINFOA OSVERSIONINFO;
        typedef OSVERSIONINFOEXA OSVERSIONINFOEX;
    #endif

    // Stub functions for system information
    inline void GetSystemInfo(LPSYSTEM_INFO lpSystemInfo)
    {
        if (!lpSystemInfo) return;
        memset(lpSystemInfo, 0, sizeof(SYSTEM_INFO));
        #ifdef __x86_64__
            lpSystemInfo->wProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;
        #else
            lpSystemInfo->wProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL;
        #endif
        lpSystemInfo->dwNumberOfProcessors = 1;
        lpSystemInfo->dwPageSize = 4096;
    }

    inline BOOL GetVersionEx(OSVERSIONINFO* lpVersionInfo)
    {
        if (!lpVersionInfo) return FALSE;
        // Stub - return fake version info
        lpVersionInfo->dwMajorVersion = 10;
        lpVersionInfo->dwMinorVersion = 0;
        lpVersionInfo->dwBuildNumber = 19045;
        lpVersionInfo->dwPlatformId = 2; // VER_PLATFORM_WIN32_NT
        wcscpy(lpVersionInfo->szCSDVersion, L"");
        return TRUE;
    }

    // PE file structures (needed for binary analysis)
    #define IMAGE_DOS_SIGNATURE                 0x5A4D      // MZ
    #define IMAGE_NT_SIGNATURE                  0x00004550  // PE00
    #define IMAGE_FILE_MACHINE_I386             0x014c
    #define IMAGE_FILE_MACHINE_AMD64            0x8664
    #define IMAGE_FILE_MACHINE_IA64             0x0200
    #define IMAGE_FILE_MACHINE_ARM              0x01c0
    #define IMAGE_FILE_MACHINE_ARM64            0xAA64

    #define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
    #define IMAGE_DIRECTORY_ENTRY_EXPORT        0
    #define IMAGE_DIRECTORY_ENTRY_IMPORT        1
    #define IMAGE_DIRECTORY_ENTRY_RESOURCE      2
    #define IMAGE_DIRECTORY_ENTRY_BASERELOC     5
    #define IMAGE_DIRECTORY_ENTRY_DEBUG         6
    #define IMAGE_DIRECTORY_ENTRY_TLS           9
    #define IMAGE_DIRECTORY_ENTRY_IAT           12
    #define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT  11

    #define IMAGE_SIZEOF_SHORT_NAME             8

    // Section characteristics
    #define IMAGE_SCN_CNT_CODE                  0x00000020
    #define IMAGE_SCN_CNT_INITIALIZED_DATA      0x00000040
    #define IMAGE_SCN_CNT_UNINITIALIZED_DATA    0x00000080
    #define IMAGE_SCN_MEM_EXECUTE               0x20000000
    #define IMAGE_SCN_MEM_READ                  0x40000000
    #define IMAGE_SCN_MEM_WRITE                 0x80000000

    #pragma pack(push, 1)

    typedef struct _IMAGE_DOS_HEADER {
        WORD   e_magic;
        WORD   e_cblp;
        WORD   e_cp;
        WORD   e_crlc;
        WORD   e_cparhdr;
        WORD   e_minalloc;
        WORD   e_maxalloc;
        WORD   e_ss;
        WORD   e_sp;
        WORD   e_csum;
        WORD   e_ip;
        WORD   e_cs;
        WORD   e_lfarlc;
        WORD   e_ovno;
        WORD   e_res[4];
        WORD   e_oemid;
        WORD   e_oeminfo;
        WORD   e_res2[10];
        LONG   e_lfanew;
    } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

    typedef struct _IMAGE_FILE_HEADER {
        WORD    Machine;
        WORD    NumberOfSections;
        DWORD   TimeDateStamp;
        DWORD   PointerToSymbolTable;
        DWORD   NumberOfSymbols;
        WORD    SizeOfOptionalHeader;
        WORD    Characteristics;
    } IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

    typedef struct _IMAGE_DATA_DIRECTORY {
        DWORD   VirtualAddress;
        DWORD   Size;
    } IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

    typedef struct _IMAGE_OPTIONAL_HEADER32 {
        WORD    Magic;
        BYTE    MajorLinkerVersion;
        BYTE    MinorLinkerVersion;
        DWORD   SizeOfCode;
        DWORD   SizeOfInitializedData;
        DWORD   SizeOfUninitializedData;
        DWORD   AddressOfEntryPoint;
        DWORD   BaseOfCode;
        DWORD   BaseOfData;
        DWORD   ImageBase;
        DWORD   SectionAlignment;
        DWORD   FileAlignment;
        WORD    MajorOperatingSystemVersion;
        WORD    MinorOperatingSystemVersion;
        WORD    MajorImageVersion;
        WORD    MinorImageVersion;
        WORD    MajorSubsystemVersion;
        WORD    MinorSubsystemVersion;
        DWORD   Win32VersionValue;
        DWORD   SizeOfImage;
        DWORD   SizeOfHeaders;
        DWORD   CheckSum;
        WORD    Subsystem;
        WORD    DllCharacteristics;
        DWORD   SizeOfStackReserve;
        DWORD   SizeOfStackCommit;
        DWORD   SizeOfHeapReserve;
        DWORD   SizeOfHeapCommit;
        DWORD   LoaderFlags;
        DWORD   NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    } IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

    typedef struct _IMAGE_OPTIONAL_HEADER64 {
        WORD        Magic;
        BYTE        MajorLinkerVersion;
        BYTE        MinorLinkerVersion;
        DWORD       SizeOfCode;
        DWORD       SizeOfInitializedData;
        DWORD       SizeOfUninitializedData;
        DWORD       AddressOfEntryPoint;
        DWORD       BaseOfCode;
        QWORD       ImageBase;
        DWORD       SectionAlignment;
        DWORD       FileAlignment;
        WORD        MajorOperatingSystemVersion;
        WORD        MinorOperatingSystemVersion;
        WORD        MajorImageVersion;
        WORD        MinorImageVersion;
        WORD        MajorSubsystemVersion;
        WORD        MinorSubsystemVersion;
        DWORD       Win32VersionValue;
        DWORD       SizeOfImage;
        DWORD       SizeOfHeaders;
        DWORD       CheckSum;
        WORD        Subsystem;
        WORD        DllCharacteristics;
        QWORD       SizeOfStackReserve;
        QWORD       SizeOfStackCommit;
        QWORD       SizeOfHeapReserve;
        QWORD       SizeOfHeapCommit;
        DWORD       LoaderFlags;
        DWORD       NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    } IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

    #ifdef __LP64__
        typedef IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER;
        typedef PIMAGE_OPTIONAL_HEADER64 PIMAGE_OPTIONAL_HEADER;
    #else
        typedef IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER;
        typedef PIMAGE_OPTIONAL_HEADER32 PIMAGE_OPTIONAL_HEADER;
    #endif

    typedef struct _IMAGE_NT_HEADERS32 {
        DWORD Signature;
        IMAGE_FILE_HEADER FileHeader;
        IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    } IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

    typedef struct _IMAGE_NT_HEADERS64 {
        DWORD Signature;
        IMAGE_FILE_HEADER FileHeader;
        IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    } IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

    // Note: IMAGE_NT_HEADERS is for analyzing PE files, not for native execution
    // Default to 32-bit variant - code should use explicit 32/64 types when needed
    typedef IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS;
    typedef PIMAGE_NT_HEADERS32 PIMAGE_NT_HEADERS;

    typedef struct _IMAGE_SECTION_HEADER {
        BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
        union {
            DWORD   PhysicalAddress;
            DWORD   VirtualSize;
        } Misc;
        DWORD   VirtualAddress;
        DWORD   SizeOfRawData;
        DWORD   PointerToRawData;
        DWORD   PointerToRelocations;
        DWORD   PointerToLinenumbers;
        WORD    NumberOfRelocations;
        WORD    NumberOfLinenumbers;
        DWORD   Characteristics;
    } IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

    typedef struct _IMAGE_EXPORT_DIRECTORY {
        DWORD   Characteristics;
        DWORD   TimeDateStamp;
        WORD    MajorVersion;
        WORD    MinorVersion;
        DWORD   Name;
        DWORD   Base;
        DWORD   NumberOfFunctions;
        DWORD   NumberOfNames;
        DWORD   AddressOfFunctions;
        DWORD   AddressOfNames;
        DWORD   AddressOfNameOrdinals;
    } IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

    typedef struct _IMAGE_IMPORT_DESCRIPTOR {
        union {
            DWORD   Characteristics;
            DWORD   OriginalFirstThunk;
        };
        DWORD   TimeDateStamp;
        DWORD   ForwarderChain;
        DWORD   Name;
        DWORD   FirstThunk;
    } IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;

    typedef struct _IMAGE_THUNK_DATA32 {
        union {
            DWORD ForwarderString;
            DWORD Function;
            DWORD Ordinal;
            DWORD AddressOfData;
        } u1;
    } IMAGE_THUNK_DATA32, *PIMAGE_THUNK_DATA32;

    typedef struct _IMAGE_THUNK_DATA64 {
        union {
            QWORD ForwarderString;
            QWORD Function;
            QWORD Ordinal;
            QWORD AddressOfData;
        } u1;
    } IMAGE_THUNK_DATA64, *PIMAGE_THUNK_DATA64;

    #ifdef __LP64__
        typedef IMAGE_THUNK_DATA64 IMAGE_THUNK_DATA;
        typedef PIMAGE_THUNK_DATA64 PIMAGE_THUNK_DATA;
    #else
        typedef IMAGE_THUNK_DATA32 IMAGE_THUNK_DATA;
        typedef PIMAGE_THUNK_DATA32 PIMAGE_THUNK_DATA;
    #endif

    typedef struct _IMAGE_IMPORT_BY_NAME {
        WORD    Hint;
        CHAR    Name[1];
    } IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

    #pragma pack(pop)

    // Memory protection constants (used in PE analysis)
    #define PAGE_NOACCESS          0x01
    #define PAGE_READONLY          0x02
    #define PAGE_READWRITE         0x04
    #define PAGE_WRITECOPY         0x08
    #define PAGE_EXECUTE           0x10
    #define PAGE_EXECUTE_READ      0x20
    #define PAGE_EXECUTE_READWRITE 0x40
    #define PAGE_EXECUTE_WRITECOPY 0x80

    // Memory state constants
    #define MEM_COMMIT             0x1000
    #define MEM_RESERVE            0x2000
    #define MEM_FREE               0x10000
    #define MEM_IMAGE              0x1000000

    // Relocation types
    #define IMAGE_REL_BASED_ABSOLUTE              0
    #define IMAGE_REL_BASED_HIGH                  1
    #define IMAGE_REL_BASED_LOW                   2
    #define IMAGE_REL_BASED_HIGHLOW               3
    #define IMAGE_REL_BASED_HIGHADJ               4
    #define IMAGE_REL_BASED_DIR64                 10

    // Invalid handle value
    #define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)

    // Generic access rights
    #define GENERIC_READ           0x80000000
    #define GENERIC_WRITE          0x40000000
    #define GENERIC_EXECUTE        0x20000000
    #define GENERIC_ALL            0x10000000

    // PE optional header magic numbers
    #define IMAGE_NT_OPTIONAL_HDR32_MAGIC      0x10b
    #define IMAGE_NT_OPTIONAL_HDR64_MAGIC      0x20b

    // Debug directory structure
    #define IMAGE_DEBUG_TYPE_UNKNOWN          0
    #define IMAGE_DEBUG_TYPE_COFF             1
    #define IMAGE_DEBUG_TYPE_CODEVIEW         2
    #define IMAGE_DEBUG_TYPE_FPO              3
    #define IMAGE_DEBUG_TYPE_MISC             4
    #define IMAGE_DEBUG_TYPE_EXCEPTION        5
    #define IMAGE_DEBUG_TYPE_FIXUP            6
    #define IMAGE_DEBUG_TYPE_OMAP_TO_SRC      7
    #define IMAGE_DEBUG_TYPE_OMAP_FROM_SRC    8
    #define IMAGE_DEBUG_TYPE_BORLAND          9
    #define IMAGE_DEBUG_TYPE_RESERVED10       10
    #define IMAGE_DEBUG_TYPE_CLSID            11

    #pragma pack(push, 1)

    typedef struct _IMAGE_DEBUG_DIRECTORY {
        DWORD   Characteristics;
        DWORD   TimeDateStamp;
        WORD    MajorVersion;
        WORD    MinorVersion;
        DWORD   Type;
        DWORD   SizeOfData;
        DWORD   AddressOfRawData;
        DWORD   PointerToRawData;
    } IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

    #pragma pack(pop)

    // Memory protection and allocation types
    typedef struct _MEMORY_BASIC_INFORMATION {
        PVOID BaseAddress;
        PVOID AllocationBase;
        DWORD AllocationProtect;
        SIZE_T RegionSize;
        DWORD State;
        DWORD Protect;
        DWORD Type;
    } MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

    // Memory query function - stub for non-Windows (returns failure)
    inline SIZE_T VirtualQueryEx(
        HANDLE hProcess,
        LPCVOID lpAddress,
        PMEMORY_BASIC_INFORMATION lpBuffer,
        SIZE_T dwLength)
    {
        (void)hProcess;
        (void)lpAddress;
        (void)lpBuffer;
        (void)dwLength;
        // On non-Windows platforms, memory querying of remote processes is not supported
        // Return 0 to indicate failure
        return 0;
    }

    // Module and procedure address functions - stubs for non-Windows
    inline HANDLE GetCurrentProcess()
    {
        // Return a dummy handle - on non-Windows, process operations are not supported
        return (HANDLE)-1;
    }

    inline HMODULE GetModuleHandleA(LPCSTR lpModuleName)
    {
        (void)lpModuleName;
        return NULL;
    }

    inline HMODULE GetModuleHandleW(LPCWSTR lpModuleName)
    {
        (void)lpModuleName;
        return NULL;
    }

    inline PVOID GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
    {
        (void)hModule;
        (void)lpProcName;
        return NULL;
    }

    // Always use W version on non-Windows since code uses L"..." strings
    #define GetModuleHandle GetModuleHandleW
    #define CreateFile CreateFileW
    #define CreateFileMapping CreateFileMappingW

    // Error handling functions (stubs for non-Windows)
    inline DWORD GetLastError()
    {
        return 0; // Not supported on non-Windows
    }

    // Windows error constants
    #define ERROR_SUCCESS              0
    #define ERROR_ALREADY_EXISTS       183

    // File I/O constants
    #define FILE_BEGIN           0
    #define FILE_CURRENT         1
    #define FILE_END             2
    #define FILE_SHARE_READ      0x00000001
    #define FILE_SHARE_WRITE     0x00000002
    #define OPEN_EXISTING        3
    #define CREATE_ALWAYS        2
    #define GENERIC_READ         0x80000000
    #define GENERIC_WRITE        0x40000000
    #define FILE_ATTRIBUTE_NORMAL 0x00000080

    // Cross-platform file I/O wrappers using POSIX APIs
    #include <fcntl.h>
    #include <unistd.h>
    #include <sys/stat.h>

    // Wrapper for CreateFile -> open()
    inline HANDLE CreateFileA(
        LPCSTR lpFileName,
        DWORD dwDesiredAccess,
        DWORD dwShareMode,
        LPVOID lpSecurityAttributes,
        DWORD dwCreationDisposition,
        DWORD dwFlagsAndAttributes,
        HANDLE hTemplateFile)
    {
        (void)dwShareMode;
        (void)lpSecurityAttributes;
        (void)dwFlagsAndAttributes;
        (void)hTemplateFile;

        int flags = 0;
        if (dwDesiredAccess & GENERIC_READ && dwDesiredAccess & GENERIC_WRITE) {
            flags = O_RDWR;
        } else if (dwDesiredAccess & GENERIC_WRITE) {
            flags = O_WRONLY;
        } else {
            flags = O_RDONLY;
        }

        if (dwCreationDisposition == CREATE_ALWAYS) {
            flags |= O_CREAT | O_TRUNC;
        }

        int fd = open(lpFileName, flags, 0644);
        if (fd == -1) {
            return INVALID_HANDLE_VALUE;
        }
        return (HANDLE)(intptr_t)fd;
    }

    inline HANDLE CreateFileW(
        LPCWSTR lpFileName,
        DWORD dwDesiredAccess,
        DWORD dwShareMode,
        LPVOID lpSecurityAttributes,
        DWORD dwCreationDisposition,
        DWORD dwFlagsAndAttributes,
        HANDLE hTemplateFile)
    {
        // Convert wide string to narrow string
        size_t len = wcslen(lpFileName);
        char* narrowPath = new char[len * 4 + 1];
        wcstombs(narrowPath, lpFileName, len * 4 + 1);

        HANDLE result = CreateFileA(narrowPath, dwDesiredAccess, dwShareMode,
                                     lpSecurityAttributes, dwCreationDisposition,
                                     dwFlagsAndAttributes, hTemplateFile);
        delete[] narrowPath;
        return result;
    }

    // Wrapper for ReadFile -> read()
    inline BOOL ReadFile(
        HANDLE hFile,
        LPVOID lpBuffer,
        DWORD nNumberOfBytesToRead,
        LPDWORD lpNumberOfBytesRead,
        LPVOID lpOverlapped)
    {
        (void)lpOverlapped;

        int fd = (int)(intptr_t)hFile;
        ssize_t bytesRead = read(fd, lpBuffer, nNumberOfBytesToRead);

        if (bytesRead == -1) {
            if (lpNumberOfBytesRead) {
                *lpNumberOfBytesRead = 0;
            }
            return FALSE;
        }

        if (lpNumberOfBytesRead) {
            *lpNumberOfBytesRead = (DWORD)bytesRead;
        }
        return TRUE;
    }

    // Wrapper for WriteFile -> write()
    inline BOOL WriteFile(
        HANDLE hFile,
        LPCVOID lpBuffer,
        DWORD nNumberOfBytesToWrite,
        LPDWORD lpNumberOfBytesWritten,
        LPVOID lpOverlapped)
    {
        (void)lpOverlapped;

        int fd = (int)(intptr_t)hFile;
        ssize_t bytesWritten = write(fd, lpBuffer, nNumberOfBytesToWrite);

        if (bytesWritten == -1) {
            if (lpNumberOfBytesWritten) {
                *lpNumberOfBytesWritten = 0;
            }
            return FALSE;
        }

        if (lpNumberOfBytesWritten) {
            *lpNumberOfBytesWritten = (DWORD)bytesWritten;
        }
        return TRUE;
    }

    // Wrapper for SetFilePointer -> lseek()
    inline DWORD SetFilePointer(
        HANDLE hFile,
        LONG lDistanceToMove,
        PLONG lpDistanceToMoveHigh,
        DWORD dwMoveMethod)
    {
        int fd = (int)(intptr_t)hFile;
        int whence;

        switch (dwMoveMethod) {
            case FILE_BEGIN:
                whence = SEEK_SET;
                break;
            case FILE_CURRENT:
                whence = SEEK_CUR;
                break;
            case FILE_END:
                whence = SEEK_END;
                break;
            default:
                return (DWORD)-1;
        }

        off_t offset = lDistanceToMove;
        if (lpDistanceToMoveHigh) {
            offset |= ((off_t)*lpDistanceToMoveHigh) << 32;
        }

        off_t newPos = lseek(fd, offset, whence);
        if (newPos == -1) {
            return (DWORD)-1;
        }

        if (lpDistanceToMoveHigh) {
            *lpDistanceToMoveHigh = (LONG)(newPos >> 32);
        }

        return (DWORD)(newPos & 0xFFFFFFFF);
    }

    // Wrapper for GetFileSize -> fstat()
    inline DWORD GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh)
    {
        int fd = (int)(intptr_t)hFile;
        struct stat st;

        if (fstat(fd, &st) == -1) {
            return (DWORD)-1;
        }

        if (lpFileSizeHigh) {
            *lpFileSizeHigh = (DWORD)(st.st_size >> 32);
        }

        return (DWORD)(st.st_size & 0xFFFFFFFF);
    }

    // Wrapper for CloseHandle -> close()
    inline BOOL CloseHandle(HANDLE hObject)
    {
        if (hObject == INVALID_HANDLE_VALUE || hObject == NULL) {
            return FALSE;
        }

        int fd = (int)(intptr_t)hObject;
        return close(fd) == 0 ? TRUE : FALSE;
    }

    // Wrapper for SetEndOfFile -> ftruncate()
    inline BOOL SetEndOfFile(HANDLE hFile)
    {
        int fd = (int)(intptr_t)hFile;
        off_t currentPos = lseek(fd, 0, SEEK_CUR);
        if (currentPos == -1) {
            return FALSE;
        }
        return ftruncate(fd, currentPos) == 0 ? TRUE : FALSE;
    }

    // Memory mapping constants
    #define PAGE_READONLY          0x02
    #define PAGE_READWRITE         0x04
    #define FILE_MAP_READ          0x0004
    #define FILE_MAP_WRITE         0x0002
    #define FILE_MAP_ALL_ACCESS    0x000f001f

    // Memory mapping functions - stubs for non-Windows
    // These operations are Windows-specific and not portable
    inline HANDLE CreateFileMappingA(
        HANDLE hFile,
        LPVOID lpFileMappingAttributes,
        DWORD flProtect,
        DWORD dwMaximumSizeHigh,
        DWORD dwMaximumSizeLow,
        LPCSTR lpName)
    {
        (void)hFile;
        (void)lpFileMappingAttributes;
        (void)flProtect;
        (void)dwMaximumSizeHigh;
        (void)dwMaximumSizeLow;
        (void)lpName;
        // Not supported on non-Windows platforms
        return NULL;
    }

    inline HANDLE CreateFileMappingW(
        HANDLE hFile,
        LPVOID lpFileMappingAttributes,
        DWORD flProtect,
        DWORD dwMaximumSizeHigh,
        DWORD dwMaximumSizeLow,
        LPCWSTR lpName)
    {
        (void)hFile;
        (void)lpFileMappingAttributes;
        (void)flProtect;
        (void)dwMaximumSizeHigh;
        (void)dwMaximumSizeLow;
        (void)lpName;
        // Not supported on non-Windows platforms
        return NULL;
    }

    inline LPVOID MapViewOfFile(
        HANDLE hFileMappingObject,
        DWORD dwDesiredAccess,
        DWORD dwFileOffsetHigh,
        DWORD dwFileOffsetLow,
        SIZE_T dwNumberOfBytesToMap)
    {
        (void)hFileMappingObject;
        (void)dwDesiredAccess;
        (void)dwFileOffsetHigh;
        (void)dwFileOffsetLow;
        (void)dwNumberOfBytesToMap;
        // Not supported on non-Windows platforms
        return NULL;
    }

    inline BOOL UnmapViewOfFile(LPCVOID lpBaseAddress)
    {
        (void)lpBaseAddress;
        // Not supported on non-Windows platforms
        return FALSE;
    }

    // PE checksum function - stub for non-Windows
    typedef struct _IMAGE_NT_HEADERS32 *PIMAGE_NT_HEADERS32;
    inline PIMAGE_NT_HEADERS32 CheckSumMappedFile(
        PVOID BaseAddress,
        DWORD FileLength,
        LPDWORD HeaderSum,
        LPDWORD CheckSum)
    {
        (void)BaseAddress;
        (void)FileLength;
        (void)HeaderSum;
        (void)CheckSum;
        // Not supported on non-Windows platforms
        return NULL;
    }

    // PE helper macro
    #define IMAGE_FIRST_SECTION(ntheader) \
        ((PIMAGE_SECTION_HEADER)((ULONG_PTR)(ntheader) + \
        offsetof(IMAGE_NT_HEADERS, OptionalHeader) + \
        ((ntheader))->FileHeader.SizeOfOptionalHeader))

    // PE Import ordinal macros
    #ifdef __LP64__
        #define IMAGE_ORDINAL_FLAG 0x8000000000000000ULL
        #define IMAGE_ORDINAL(Ordinal) ((Ordinal) & 0xFFFF)
    #else
        #define IMAGE_ORDINAL_FLAG 0x80000000
        #define IMAGE_ORDINAL(Ordinal) ((Ordinal) & 0xFFFF)
    #endif

    // errno_t type for secure functions (define before use)
    #ifndef _ERRNO_T_DEFINED
    #define _ERRNO_T_DEFINED
    typedef int errno_t;
    #endif

    // Additional errno values
    #ifndef EINVAL
    #define EINVAL 22
    #endif
    #ifndef ERANGE
    #define ERANGE 34
    #endif

    // Secure string function replacements
    inline errno_t memcpy_s(void* dest, size_t destSize, const void* src, size_t count)
    {
        if (!dest || !src) return EINVAL;
        if (count > destSize) return ERANGE;
        memcpy(dest, src, count);
        return 0;
    }

    inline int swprintf_s(wchar_t* buffer, size_t sizeOfBuffer, const wchar_t* format, ...)
    {
        va_list args;
        va_start(args, format);
        int result = vswprintf(buffer, sizeOfBuffer, format, args);
        va_end(args);
        return result;
    }

    inline int sprintf_s(char* buffer, size_t sizeOfBuffer, const char* format, ...)
    {
        va_list args;
        va_start(args, format);
        int result = vsnprintf(buffer, sizeOfBuffer, format, args);
        va_end(args);
        return result;
    }

    inline errno_t strcpy_s(char* dest, size_t destSize, const char* src)
    {
        if (!dest || !src) return EINVAL;
        size_t len = strlen(src);
        if (len >= destSize) return ERANGE;
        strcpy(dest, src);
        return 0;
    }

    // Template overload for array destSizes (matches Windows behavior)
    template<size_t N>
    inline errno_t strcpy_s(char (&dest)[N], const char* src)
    {
        return strcpy_s(dest, N, src);
    }

    inline errno_t wcscpy_s(wchar_t* dest, size_t destSize, const wchar_t* src)
    {
        if (!dest || !src) return EINVAL;
        size_t len = wcslen(src);
        if (len >= destSize) return ERANGE;
        wcscpy(dest, src);
        return 0;
    }

    // _countof macro for array element counting
    #ifndef _countof
    #define _countof(array) (sizeof(array) / sizeof(array[0]))
    #endif

    inline errno_t strncpy_s(char* dest, size_t destSize, const char* src, size_t count)
    {
        if (!dest || !src) return EINVAL;
        size_t len = strlen(src);
        size_t copyLen = (count < len) ? count : len;
        if (copyLen >= destSize) return ERANGE;
        strncpy(dest, src, copyLen);
        dest[copyLen] = '\0';
        return 0;
    }

    inline errno_t wcsncpy_s(wchar_t* dest, size_t destSize, const wchar_t* src, size_t count)
    {
        if (!dest || !src) return EINVAL;
        size_t len = wcslen(src);
        size_t copyLen = (count < len) ? count : len;
        if (copyLen >= destSize) return ERANGE;
        wcsncpy(dest, src, copyLen);
        dest[copyLen] = L'\0';
        return 0;
    }

#endif // !_WIN32
