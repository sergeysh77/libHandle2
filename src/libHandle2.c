// src/libHandle2.c
#include "private.h"

wchar_t g_lastError[512] = {0};

void SetScannerError(const wchar_t* error) {
    wcsncpy(g_lastError, error, 511);
    g_lastError[511] = L'\0';
}

const wchar_t* GetLastScannerError(void) {
    return g_lastError;
}

const char* GetScannerVersion(void) {
    return "1.0.0";
}

void EnableDebugPrivilege(void) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
        return;
    
    LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tp.Privileges[0].Luid);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
    CloseHandle(hToken);
}

void InitDefaultOptions(ScanOptions* options) {
    if (options) {
        options->includeModules = TRUE;
        options->includeHandleTypes = TRUE;
        options->timeoutMs = DEFAULT_TIMEOUT_MS;
        options->maxResults = DEFAULT_MAX_RESULTS;
    }
}