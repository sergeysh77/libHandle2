// src/scanner.c
#include "private.h"

// Global variables for storing last results
static ProcessLockInfo* g_last_results = NULL;
static int g_last_count = 0;

// Cache for "File" type index (common for files and folders)
static int g_file_type_index = 0;

// Function to determine File type index (common for files and folders)
static int GetFileTypeIndex(void) {
    if (g_file_type_index != 0) return g_file_type_index;
    
    int count;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* handles = QueryAllHandles(&count);
    if (!handles) {
        g_file_type_index = 0;
        return 0;
    }
    
    // Look for handles in our own process (open folder from which it was launched)
    DWORD currentPid = GetCurrentProcessId();
    for (int i = 0; i < count; i++) {
        if ((DWORD)handles[i].UniqueProcessId == currentPid) {
            HANDLE hDup = NULL;
            DuplicateHandle(GetCurrentProcess(), handles[i].HandleValue,
                           GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS);
            if (hDup) {
                wchar_t* type = GetHandleTypeWithTimeout(hDup, 50);
                if (type && wcscmp(type, L"File") == 0) {
                    g_file_type_index = handles[i].ObjectTypeIndex;
                    free(type);
                    CloseHandle(hDup);
                    free(handles);
                    return g_file_type_index;
                }
                CloseHandle(hDup);
            }
        }
    }
    
    free(handles);
    g_file_type_index = 0;
    return 0;
}

ProcessLockInfo* ScanFolder(const wchar_t* folderPath, int* resultCount, ScanOptions* options) {
    ProcessLockInfo* results = NULL;
    SYSTEM_HANDLE_INFORMATION_EX* handleInfo = NULL;
    ULONG bufSize = 0x100000;
    NTSTATUS status;
    
    // Clear previous results if they exist
    if (g_last_results) {
        FreeScanResults(g_last_results, g_last_count);
        g_last_results = NULL;
        g_last_count = 0;
    }
    
    SetScannerError(L"");
    EnableDebugPrivilege();
    LoadNtFunctions();
    
    if (!NtQuerySystemInformation) {
        SetScannerError(L"NtQuerySystemInformation not available");
        return NULL;
    }
    
    // Determine file type index
    int fileTypeIndex = GetFileTypeIndex();
    
    // Normalize folder path
    wchar_t targetPath[MAX_PATH];
    wcscpy(targetPath, folderPath);
    if (wcsncmp(targetPath, L"\\\\?\\", 4) == 0) {
        wcscpy(targetPath, targetPath + 4);
    }
    
    // Create searchPath with backslash
    wchar_t searchPath[MAX_PATH];
    wcscpy(searchPath, targetPath);
    size_t pathLen = wcslen(searchPath);
    if (pathLen > 0 && searchPath[pathLen - 1] != L'\\') {
        wcscat(searchPath, L"\\");
    }
    
    // Create pathWithoutSlash without trailing slash
    wchar_t pathWithoutSlash[MAX_PATH];
    wcscpy(pathWithoutSlash, targetPath);
    pathLen = wcslen(pathWithoutSlash);
    if (pathLen > 0 && pathWithoutSlash[pathLen - 1] == L'\\') {
        pathWithoutSlash[pathLen - 1] = L'\0';
    }
    
    while (1) {
        handleInfo = (SYSTEM_HANDLE_INFORMATION_EX*)malloc(bufSize);
        if (!handleInfo) {
            SetScannerError(L"Failed to allocate memory");
            return NULL;
        }
        
        status = NtQuerySystemInformation(SystemExtendedHandleInformation, handleInfo, bufSize, NULL);
        
        if (status == STATUS_SUCCESS) break;
        
        if (status != STATUS_INFO_LENGTH_MISMATCH) {
            free(handleInfo);
            SetScannerError(L"NtQuerySystemInformation failed");
            return NULL;
        }
        
        free(handleInfo);
        bufSize *= 2;
    }
    
    ULONG handleCount = (ULONG)handleInfo->NumberOfHandles;
    HANDLE hCurrent = GetCurrentProcess();
    
    int maxResults = options ? options->maxResults : DEFAULT_MAX_RESULTS;
    results = (ProcessLockInfo*)malloc(maxResults * sizeof(ProcessLockInfo));
    memset(results, 0, maxResults * sizeof(ProcessLockInfo));
    *resultCount = 0;
    
    for (ULONG i = 0; i < handleCount && *resultCount < maxResults; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* entry = &handleInfo->Handles[i];
        
        // Filter out handles that are not of type "File"
        if (fileTypeIndex != 0 && entry->ObjectTypeIndex != fileTypeIndex) continue;
        
        DWORD pid = (DWORD)(ULONG_PTR)entry->UniqueProcessId;
        
        if (pid == 0 || pid == 4) continue;
        
        HANDLE hProcess = OpenProcessCached(pid);
        if (!hProcess) continue;
        
        HANDLE hDup = NULL;
        if (!DuplicateHandle(hProcess, entry->HandleValue, hCurrent, &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            continue;
        }
        
        int timeout = options ? options->timeoutMs : DEFAULT_TIMEOUT_MS;
        wchar_t* type = GetHandleTypeWithTimeout(hDup, timeout);
        
        if (type && wcscmp(type, L"File") == 0) {
            wchar_t* filePath = GetFilePathWithTimeout(hDup, timeout);
            
            if (filePath) {
                if (wcsncmp(filePath, L"\\\\?\\", 4) == 0) {
                    wcscpy(filePath, filePath + 4);
                }
                
                BOOL isMatch = (_wcsicmp(filePath, pathWithoutSlash) == 0) ||
                               (_wcsnicmp(filePath, searchPath, wcslen(searchPath)) == 0);
                
                if (isMatch) {
                    ProcessLockInfo* item = &results[*resultCount];
                    memset(item, 0, sizeof(ProcessLockInfo));
                    
                    item->pid = pid;
                    item->processPath = GetProcessPath(pid);
                    item->filePath = filePath;
                    filePath = NULL;
                    item->grantedAccess = entry->GrantedAccess;
                    item->attributes = entry->HandleAttributes;
                    item->kernelAddress = (ULONG_PTR)entry->Object;
                    item->objectTypeIndex = entry->ObjectTypeIndex;
                    
                    if (options && options->includeHandleTypes) {
                        item->handleType = type;
                        type = NULL;
                    }
                    
                    HANDLE hProc = OpenProcessCached(pid);
                    GetProcessUser(hProc, item->userName, item->domainName);
                    
                    if (options && options->includeModules) {
                        item->moduleNames = GetProcessModules(hProc, &item->moduleCount);
                    }
                    
                    (*resultCount)++;
                }
            }
            
            if (filePath) free(filePath);
        }
        
        if (type) free(type);
        CloseHandle(hDup);
    }
    
    free(handleInfo);
    
    // Save results
    g_last_results = results;
    g_last_count = *resultCount;
    
    return results;
}

ProcessLockInfo* ScanFile(const wchar_t* filePath, int* resultCount, ScanOptions* options) {
    ProcessLockInfo* results = NULL;
    SYSTEM_HANDLE_INFORMATION_EX* handleInfo = NULL;
    ULONG bufSize = 0x100000;
    NTSTATUS status;
    
    // Clear previous results if they exist
    if (g_last_results) {
        FreeScanResults(g_last_results, g_last_count);
        g_last_results = NULL;
        g_last_count = 0;
    }
    
    SetScannerError(L"");
    EnableDebugPrivilege();
    LoadNtFunctions();
    
    if (!NtQuerySystemInformation) {
        SetScannerError(L"NtQuerySystemInformation not available");
        return NULL;
    }
    
    // Determine index for files
    int fileTypeIndex = GetFileTypeIndex();
    
    // Normalize file path
    wchar_t targetPath[MAX_PATH];
    wcscpy(targetPath, filePath);
    if (wcsncmp(targetPath, L"\\\\?\\", 4) == 0) {
        wcscpy(targetPath, targetPath + 4);
    }
    
    while (1) {
        handleInfo = (SYSTEM_HANDLE_INFORMATION_EX*)malloc(bufSize);
        if (!handleInfo) {
            SetScannerError(L"Failed to allocate memory");
            return NULL;
        }
        
        status = NtQuerySystemInformation(SystemExtendedHandleInformation, handleInfo, bufSize, NULL);
        
        if (status == STATUS_SUCCESS) break;
        
        if (status != STATUS_INFO_LENGTH_MISMATCH) {
            free(handleInfo);
            SetScannerError(L"NtQuerySystemInformation failed");
            return NULL;
        }
        
        free(handleInfo);
        bufSize *= 2;
    }
    
    ULONG handleCount = (ULONG)handleInfo->NumberOfHandles;
    HANDLE hCurrent = GetCurrentProcess();
    
    int maxResults = options ? options->maxResults : DEFAULT_MAX_RESULTS;
    results = (ProcessLockInfo*)malloc(maxResults * sizeof(ProcessLockInfo));
    memset(results, 0, maxResults * sizeof(ProcessLockInfo));
    *resultCount = 0;
    
    for (ULONG i = 0; i < handleCount && *resultCount < maxResults; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* entry = &handleInfo->Handles[i];
        
        // Filter out handles that are not of type "File"
        if (fileTypeIndex != 0 && entry->ObjectTypeIndex != fileTypeIndex) continue;
        
        DWORD pid = (DWORD)(ULONG_PTR)entry->UniqueProcessId;
        
        if (pid == 0 || pid == 4 || pid == GetCurrentProcessId()) continue;
        
        HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProcess) continue;
        
        HANDLE hDup = NULL;
        if (!DuplicateHandle(hProcess, entry->HandleValue, hCurrent, &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            CloseHandle(hProcess);
            continue;
        }
        
        int timeout = options ? options->timeoutMs : DEFAULT_TIMEOUT_MS;
        wchar_t* type = GetHandleTypeWithTimeout(hDup, timeout);
        
        if (type && wcscmp(type, L"File") == 0) {
            wchar_t* foundPath = GetFilePathWithTimeout(hDup, timeout);
            
            if (foundPath) {
                if (wcsncmp(foundPath, L"\\\\?\\", 4) == 0) {
                    wcscpy(foundPath, foundPath + 4);
                }
                
                // Exact match with file (without folderMatch)
                int exactMatch = (_wcsicmp(foundPath, targetPath) == 0);
                
                if (exactMatch) {
                    ProcessLockInfo* item = &results[*resultCount];
                    memset(item, 0, sizeof(ProcessLockInfo));
                    
                    item->pid = pid;
                    item->processPath = GetProcessPath(pid);
                    item->filePath = _wcsdup(targetPath);
                    item->grantedAccess = entry->GrantedAccess;
                    item->attributes = entry->HandleAttributes;
                    item->kernelAddress = (ULONG_PTR)entry->Object;
                    item->objectTypeIndex = entry->ObjectTypeIndex;
                    
                    if (options && options->includeHandleTypes) {
                        item->handleType = type;
                        type = NULL;
                    }
                    
                    GetProcessUser(hProcess, item->userName, item->domainName);
                    
                    if (options && options->includeModules) {
                        item->moduleNames = GetProcessModules(hProcess, &item->moduleCount);
                    }
                    
                    (*resultCount)++;
                }
            }
            
            if (foundPath) free(foundPath);
        }
        
        if (type) free(type);
        CloseHandle(hDup);
        CloseHandle(hProcess);
    }
    
    free(handleInfo);

    // Save results
    g_last_results = results;
    g_last_count = *resultCount;
    
    return results;
}