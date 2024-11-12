#pragma once

#ifndef __wtypes_h__
#include <wtypes.h>
#endif

#ifndef __WINDEF_
#include <windef.h>
#endif

LPCWSTR charToLPCWSTR(const char* charString);
LPSTR charToLPSTR(const char* str);
LPWSTR charToLPWSTR(const char* charString);
void setConsoleColor(int colorCode);