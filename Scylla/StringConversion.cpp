#include "StringConversion.h"
#include <cstdlib>

#ifdef _WIN32
#include <atlbase.h>
#include <atlconv.h>
#endif

const char* StringConversion::ToASCII(const wchar_t* str, char* buf, size_t bufsize)
{
#ifdef _WIN32
	ATL::CW2A str_a = str;
	strncpy_s(buf, bufsize, str_a, bufsize);
#else
	wcstombs(buf, str, bufsize);
#endif
	buf[bufsize - 1] = '\0';
	return buf;
}

const wchar_t* StringConversion::ToUTF16(const char* str, wchar_t* buf, size_t bufsize)
{
#ifdef _WIN32
	ATL::CA2W str_w = str;
	wcsncpy_s(buf, bufsize, str_w, bufsize);
#else
	mbstowcs(buf, str, bufsize);
#endif
	buf[bufsize - 1] = L'\0';
	return buf;
}
