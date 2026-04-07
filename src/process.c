// src/process.c
#include "private.h"

PROCESS_CACHE processCache[MAX_PROCESS_CACHE];
int cacheCount = 0;

HANDLE OpenProcessCached(DWORD pid) {
    for (int i = 0; i < cacheCount; i++) {
        if (processCache[i].pid == pid) {
            return processCache[i].handle;
        }
    }
    
    HANDLE hProcess = OpenProcess(
        PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 
        FALSE, pid
    );
    
    if (hProcess && cacheCount < MAX_PROCESS_CACHE) {
        processCache[cacheCount].pid = pid;
        processCache[cacheCount].handle = hProcess;
        processCache[cacheCount].path = NULL;
        cacheCount++;
    }
    return hProcess;
}

wchar_t* GetProcessPath(DWORD pid) {
    for (int i = 0; i < cacheCount; i++) {
        if (processCache[i].pid == pid && processCache[i].path) {
            return processCache[i].path;
        }
    }
    
    HANDLE hProcess = OpenProcessCached(pid);
    if (!hProcess) return NULL;
    
    wchar_t path[MAX_PATH];
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
        wchar_t* result = (wchar_t*)malloc((wcslen(path) + 1) * sizeof(wchar_t));
        if (result) {
            wcscpy(result, path);
            for (int i = 0; i < cacheCount; i++) {
                if (processCache[i].pid == pid) {
                    processCache[i].path = result;
                    break;
                }
            }
            return result;
        }
    }
    return NULL;
}

void GetProcessUser(HANDLE hProcess, wchar_t* user, wchar_t* domain) {
    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        wcscpy(user, L"");
        wcscpy(domain, L"");
        return;
    }
    
    DWORD size = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &size);
    TOKEN_USER* tokenUser = (TOKEN_USER*)malloc(size);
    
    if (GetTokenInformation(hToken, TokenUser, tokenUser, size, &size)) {
        DWORD userSize = 256;
        DWORD domainSize = 256;
        SID_NAME_USE sidUse;
        LookupAccountSidW(NULL, tokenUser->User.Sid, user, &userSize, domain, &domainSize, &sidUse);
    }
    
    free(tokenUser);
    CloseHandle(hToken);
}

wchar_t** GetProcessModules(HANDLE hProcess, int* moduleCount) {
    HMODULE modules[1024];
    DWORD needed = 0;
    wchar_t** result = NULL;
    
    *moduleCount = 0;
    
    if (!EnumProcessModules(hProcess, modules, sizeof(modules), &needed)) {
        return NULL;
    }
    
    int count = needed / sizeof(HMODULE);
    if (count > 1024) count = 1024;
    
    result = (wchar_t**)malloc(count * sizeof(wchar_t*));
    if (!result) return NULL;
    memset(result, 0, count * sizeof(wchar_t*));
    
    for (int i = 0; i < count; i++) {
        wchar_t modName[MAX_PATH];
        if (GetModuleFileNameExW(hProcess, modules[i], modName, MAX_PATH) > 0) {
            result[*moduleCount] = (wchar_t*)malloc((wcslen(modName) + 1) * sizeof(wchar_t));
            if (result[*moduleCount]) {
                wcscpy(result[*moduleCount], modName);
                (*moduleCount)++;
            }
        }
    }
    
    return result;
}

void CloseProcessCache(void) {
    for (int i = 0; i < cacheCount; i++) {
        if (processCache[i].handle) {
            CloseHandle(processCache[i].handle);
            processCache[i].handle = NULL;
        }
        if (processCache[i].path) {
            free(processCache[i].path);
            processCache[i].path = NULL;
        }
    }
    cacheCount = 0;
}