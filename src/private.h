// src/private.h
#ifndef PRIVATE_H
#define PRIVATE_H

#include "libHandle2.h"
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// NT API definitions
typedef LONG NTSTATUS;

#define STATUS_SUCCESS 0
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#define SystemExtendedHandleInformation 64
#define ObjectTypeInformation 2

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    HANDLE HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING;

typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccess;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    USHORT MaintainTypeList;
    ULONG PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION;

typedef NTSTATUS (NTAPI *pNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pNtQueryObject)(HANDLE, ULONG, PVOID, ULONG, PULONG);

#define MAX_PROCESS_CACHE 100
#define DEFAULT_TIMEOUT_MS 50
#define DEFAULT_MAX_RESULTS 10000

// Global variables
extern int g_timeoutCount;
extern wchar_t g_lastError[512];
extern pNtQuerySystemInformation NtQuerySystemInformation;
extern pNtQueryObject NtQueryObject;

typedef struct {
    DWORD pid;
    HANDLE handle;
    wchar_t* path;
} PROCESS_CACHE;

extern PROCESS_CACHE processCache[MAX_PROCESS_CACHE];
extern int cacheCount;

typedef struct {
    HANDLE h;
    void* result;
} THREAD_DATA;

// Functions from different modules
void FreeScanResults(ProcessLockInfo* results, int count);
void LoadNtFunctions(void);
void EnableDebugPrivilege(void);
void SetScannerError(const wchar_t* error);
SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* QueryAllHandles(int* count);
HANDLE OpenProcessCached(DWORD pid);
wchar_t* GetProcessPath(DWORD pid);
void GetProcessUser(HANDLE hProcess, wchar_t* user, wchar_t* domain);
wchar_t** GetProcessModules(HANDLE hProcess, int* moduleCount);
wchar_t* GetHandleTypeWithTimeout(HANDLE h, int timeoutMs);
wchar_t* GetFilePathWithTimeout(HANDLE h, int timeoutMs);
void CloseProcessCache(void);

#endif