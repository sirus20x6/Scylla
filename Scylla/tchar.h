// Compatibility header for tchar.h on non-Windows platforms
#pragma once

#ifndef _WIN32
    #include <wchar.h>

    // TCHAR is wchar_t on non-Windows
    typedef wchar_t TCHAR;

    // String macros
    #define _T(x) L##x
    #define _TEXT(x) L##x

    // String functions
    #define _tcslen wcslen
    #define _tcscpy wcscpy
    #define _tcscat wcscat
    #define _tcscmp wcscmp
    #define _tcsicmp wcscasecmp
    #define _tcsncpy wcsncpy
    #define _tcsncat wcsncat
    #define _tcsncmp wcsncmp
    #define _tcsstr wcsstr
    #define _tcschr wcschr
    #define _tcsrchr wcsrchr

#else
    #include <tchar.h>
#endif
