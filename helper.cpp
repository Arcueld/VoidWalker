#include "helper.h"


LPSTR charToLPSTR(const char* str) {
	if (str == nullptr) {
		return nullptr;
	}

	size_t len = strlen(str);

	LPSTR lpstr = (LPSTR)LocalAlloc(LPTR, len + 1);

	if (lpstr != nullptr) {
		strcpy_s(lpstr, len + 1, str);
	}

	return lpstr;
}
LPCWSTR charToLPCWSTR(const char* charString) {
	// Calculate the size needed for the wide string buffer
	int size_needed = MultiByteToWideChar(CP_ACP, 0, charString, -1, NULL, 0);

	// Allocate memory for the wide string buffer
	static wchar_t wideString[256];
	if (size_needed > sizeof(wideString) / sizeof(wideString[0])) {
		// Handle buffer size exceeded case
		return NULL;
	}

	// Perform the conversion
	MultiByteToWideChar(CP_ACP, 0, charString, -1, wideString, size_needed);

	return wideString;
}
LPWSTR charToLPWSTR(const char* charString) {
	// Calculate the size needed for the wide string buffer
	int size_needed = MultiByteToWideChar(CP_ACP, 0, charString, -1, NULL, 0);

	// Allocate memory for the wide string buffer
	static wchar_t wideString[256];  // Adjust buffer size as needed
	if (size_needed > sizeof(wideString) / sizeof(wideString[0])) {
		// Handle buffer size exceeded case
		return NULL;
	}

	// Perform the conversion
	MultiByteToWideChar(CP_ACP, 0, charString, -1, wideString, size_needed);

	return wideString;
}
void setConsoleColor(int colorCode) {
#ifdef _WIN32
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, colorCode);  // 设置颜色
#endif
}