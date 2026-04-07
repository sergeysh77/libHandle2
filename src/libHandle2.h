// src/libHandle2.h
#ifndef LIBHANDLE2_H
#define LIBHANDLE2_H

#include <windows.h>
#include <wchar.h>

#ifdef HANDLE2_EXPORTS
    #define HANDLE2_API __declspec(dllexport)
#else
    #define HANDLE2_API __declspec(dllimport)
#endif

typedef struct {
    DWORD pid;
    wchar_t* processPath;
    wchar_t* filePath;
    wchar_t userName[256];
    wchar_t domainName[256];
    wchar_t** moduleNames;
    int moduleCount;
    ULONG grantedAccess;
    wchar_t* handleType;
    ULONG_PTR kernelAddress;
    ULONG attributes;
    USHORT objectTypeIndex;
} ProcessLockInfo;

typedef struct {
    BOOL includeModules;
    BOOL includeHandleTypes;
    int timeoutMs;
    int maxResults;
} ScanOptions;

HANDLE2_API void InitDefaultOptions(ScanOptions* options);
HANDLE2_API ProcessLockInfo* ScanFolder(const wchar_t* folderPath, int* resultCount, ScanOptions* options);
HANDLE2_API ProcessLockInfo* ScanFile(const wchar_t* filePath, int* resultCount, ScanOptions* options);
// HANDLE2_API void FreeScanResults(ProcessLockInfo* results, int count);
HANDLE2_API const char* GetScannerVersion(void);
HANDLE2_API const wchar_t* GetLastScannerError(void);

#endif