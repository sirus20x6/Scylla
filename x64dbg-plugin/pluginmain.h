#pragma once

/*
 * x64dbg Plugin SDK Stub
 *
 * In production, this would be replaced with the actual x64dbg plugin SDK.
 * Download from: https://github.com/x64dbg/x64dbg
 */

#ifdef _WIN32

#include <windows.h>

// Plugin SDK version
#define PLUG_SDKVERSION 1

// Plugin structures
typedef unsigned long long duint;

typedef struct
{
    int pluginHandle;
    int sdkVersion;
    int pluginVersion;
    char pluginName[256];
} PLUG_INITSTRUCT;

typedef struct
{
    int hMenu;
} PLUG_SETUPSTRUCT;

typedef enum
{
    CB_MENUENTRY
} CBTYPE;

typedef struct
{
    int hEntry;
} PLUG_CB_MENUENTRY;

// Plugin API functions (stubs)
inline void _plugin_logputs(const char* text)
{
    OutputDebugStringA("[Scylla] ");
    OutputDebugStringA(text);
    OutputDebugStringA("\n");
}

inline void _plugin_logprintf(const char* format, ...)
{
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    _plugin_logputs(buffer);
}

inline bool _plugin_menuaddentry(int hMenu, int id, const char* title)
{
    // Stub: Would add menu entry to x64dbg
    return true;
}

inline void _plugin_menuclear(int hMenu)
{
    // Stub: Would clear menu entries
}

inline duint DbgValFromString(const char* expression)
{
    // Stub: Would evaluate x64dbg expression
    // For example: "$base" returns image base address
    if (strcmp(expression, "$base") == 0)
        return 0x400000;  // Stub value
    if (strcmp(expression, "$size") == 0)
        return 0x100000;  // Stub value
    if (strcmp(expression, "$ip") == 0)
        return 0x401000;  // Stub value
    return 0;
}

inline bool DbgMemRead(duint address, void* buffer, size_t size)
{
    // Stub: Would read debuggee memory
    return false;  // Not implemented in stub
}

inline duint DbgGetBpxHitCount(duint address)
{
    // Stub: Would get breakpoint hit count
    return 0;
}

inline duint DbgMemFindPattern(duint start, duint size, const unsigned char* pattern, size_t patternSize)
{
    // Stub: Would search for byte pattern in memory
    return 0;
}

inline bool DbgCmdExec(const char* command)
{
    // Stub: Would execute x64dbg command
    _plugin_logprintf("Execute: %s", command);
    return true;
}

// String helper
class String
{
public:
    static std::string Printf(const char* format, ...)
    {
        char buffer[1024];
        va_list args;
        va_start(args, format);
        vsnprintf(buffer, sizeof(buffer), format, args);
        va_end(args);
        return buffer;
    }
};

#endif // _WIN32
