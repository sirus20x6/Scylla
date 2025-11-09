#pragma once

#include <windows.h>

// Menu IDs
enum
{
    MENU_DUMP = 1,
    MENU_IAT,
    MENU_OEP,
    MENU_ABOUT
};

// Plugin callbacks
void MenuEntryDump();
void MenuEntryIAT();
void MenuEntryOEP();
void MenuEntryAbout();
