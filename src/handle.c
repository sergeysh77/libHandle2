// src/handle.c
#include "private.h"

int g_timeoutCount = 0;

static DWORD WINAPI GetHandleTypeThread(LPVOID lpParam) {
    THREAD_DATA* data = (THREAD_DATA*)lpParam;
    HANDLE h = data->h;
    ULONG returnLength = 0;
    
    if (!NtQueryObject) return 0;
    
    NTSTATUS status = NtQueryObject(h, ObjectTypeInformation, NULL, 0, &returnLength);
    if (status != STATUS_INFO_LENGTH_MISMATCH) return 0;
    
    OBJECT_TYPE_INFORMATION* typeInfo = (OBJECT_TYPE_INFORMATION*)malloc(returnLength);
    if (!typeInfo) return 0;
    
    status = NtQueryObject(h, ObjectTypeInformation, typeInfo, returnLength, &returnLength);
    wchar_t* result = NULL;
    
    if (status == STATUS_SUCCESS && typeInfo->TypeName.Buffer && typeInfo->TypeName.Length > 0) {
        int len = typeInfo->TypeName.Length / sizeof(wchar_t);
        result = (wchar_t*)malloc((len + 1) * sizeof(wchar_t));
        if (result) {
            wcsncpy(result, typeInfo->TypeName.Buffer, len);
            result[len] = L'\0';
        }
    }
    
    free(typeInfo);
    data->result = result;
    return 0;
}

wchar_t* GetHandleTypeWithTimeout(HANDLE h, int timeoutMs) {
    THREAD_DATA data;
    data.h = h;
    data.result = NULL;
    
    HANDLE hThread = CreateThread(NULL, 0, GetHandleTypeThread, &data, 0, NULL);
    if (!hThread) return NULL;
    
    DWORD waitResult = WaitForSingleObject(hThread, timeoutMs);
    if (waitResult == WAIT_TIMEOUT) {
        TerminateThread(hThread, 0);
        g_timeoutCount++;
        CloseHandle(hThread);
        return NULL;
    }
    
    CloseHandle(hThread);
    return (wchar_t*)data.result;
}

static DWORD WINAPI GetFilePathThread(LPVOID lpParam) {
    THREAD_DATA* data = (THREAD_DATA*)lpParam;
    HANDLE h = data->h;
    wchar_t* path = NULL;
    DWORD size = 0;
    
    size = GetFinalPathNameByHandleW(h, NULL, 0, VOLUME_NAME_DOS);
    if (size == 0) return 0;
    
    path = (wchar_t*)malloc((size + 1) * sizeof(wchar_t));
    if (!path) return 0;
    
    if (GetFinalPathNameByHandleW(h, path, size, VOLUME_NAME_DOS) == 0) {
        free(path);
        return 0;
    }
    
    path[size] = L'\0';
    
    if (wcsncmp(path, L"\\\\?\\", 4) == 0) {
        wchar_t* newPath = (wchar_t*)malloc((wcslen(path) - 3) * sizeof(wchar_t));
        if (newPath) {
            wcscpy(newPath, path + 4);
            free(path);
            data->result = newPath;
            return 0;
        }
        free(path);
        data->result = NULL;
        return 0;
    }
    
    data->result = path;
    return 0;
}

wchar_t* GetFilePathWithTimeout(HANDLE h, int timeoutMs) {
    THREAD_DATA data;
    data.h = h;
    data.result = NULL;
    
    HANDLE hThread = CreateThread(NULL, 0, GetFilePathThread, &data, 0, NULL);
    if (!hThread) return NULL;
    
    DWORD waitResult = WaitForSingleObject(hThread, timeoutMs);
    if (waitResult == WAIT_TIMEOUT) {
        TerminateThread(hThread, 0);
        g_timeoutCount++;
        CloseHandle(hThread);
        return NULL;
    }
    
    CloseHandle(hThread);
    return (wchar_t*)data.result;
}