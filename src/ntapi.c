// src/ntapi.c
#include "private.h"

pNtQuerySystemInformation NtQuerySystemInformation = NULL;
pNtQueryObject NtQueryObject = NULL;

void LoadNtFunctions(void) {
    if (NtQuerySystemInformation) return;
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
        NtQueryObject = (pNtQueryObject)GetProcAddress(hNtdll, "NtQueryObject");
    }
}

SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* QueryAllHandles(int* count) {
    ULONG bufSize = 0x100000;
    SYSTEM_HANDLE_INFORMATION_EX* handleInfo = NULL;
    NTSTATUS status;
    
    if (!NtQuerySystemInformation) {
        LoadNtFunctions();
        if (!NtQuerySystemInformation) {
            if (count) *count = 0;
            return NULL;
        }
    }
    
    while (1) {
        handleInfo = (SYSTEM_HANDLE_INFORMATION_EX*)malloc(bufSize);
        if (!handleInfo) {
            if (count) *count = 0;
            return NULL;
        }
        
        status = NtQuerySystemInformation(SystemExtendedHandleInformation, handleInfo, bufSize, NULL);
        
        if (status == STATUS_SUCCESS) {
            if (count) *count = (int)handleInfo->NumberOfHandles;
            size_t handlesSize = handleInfo->NumberOfHandles * sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX);
            SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* handles = (SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX*)malloc(handlesSize);
            if (handles) {
                memcpy(handles, handleInfo->Handles, handlesSize);
            }
            free(handleInfo);
            return handles;
        }
        
        if (status != STATUS_INFO_LENGTH_MISMATCH) {
            free(handleInfo);
            if (count) *count = 0;
            return NULL;
        }
        
        free(handleInfo);
        bufSize *= 2;
        if (bufSize > 32 * 1024 * 1024) {
            if (count) *count = 0;
            return NULL;
        }
    }
}