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
    #else
        // 32-bit
        #define PRINTF_DWORD_PTR_FULL_S "%08X"
        #define PRINTF_DWORD_PTR_HALF_S "%08X"
        #define PRINTF_DWORD_PTR_S "%X"
    #endif
    #define PRINTF_DWORD_PTR_FULL TEXT(PRINTF_DWORD_PTR_FULL_S)
    #define PRINTF_DWORD_PTR_HALF TEXT(PRINTF_DWORD_PTR_HALF_S)
    #define PRINTF_DWORD_PTR TEXT(PRINTF_DWORD_PTR_S)

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

    #define IMAGE_SIZEOF_SHORT_NAME             8

    // Section characteristics
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

    #ifdef __LP64__
        typedef IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS;
        typedef PIMAGE_NT_HEADERS64 PIMAGE_NT_HEADERS;
    #else
        typedef IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS;
        typedef PIMAGE_NT_HEADERS32 PIMAGE_NT_HEADERS;
    #endif

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

#endif // !_WIN32
