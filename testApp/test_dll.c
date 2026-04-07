// testApp/test_dll.c
#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <string.h>

// Structures from libhandle2.h
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

// Function pointers from DLL
typedef void (*InitDefaultOptionsFunc)(ScanOptions*);
typedef ProcessLockInfo* (*ScanFolderFunc)(const wchar_t*, int*, ScanOptions*);
typedef ProcessLockInfo* (*ScanFileFunc)(const wchar_t*, int*, ScanOptions*);
typedef const char* (*GetScannerVersionFunc)(void);

void print_json_string(const wchar_t* str) {
    if (!str) {
        printf("\"\"");
        return;
    }
    
    printf("\"");
    for (const wchar_t* p = str; *p; p++) {
        switch (*p) {
            case L'\\': printf("\\\\"); break;
            case L'"': printf("\\\""); break;
            case L'\n': printf("\\n"); break;
            case L'\r': printf("\\r"); break;
            case L'\t': printf("\\t"); break;
            default:
                if (*p < 0x20) {
                    printf("\\u%04X", (unsigned int)*p);
                } else {
                    putchar((char)*p);
                }
        }
    }
    printf("\"");
}

void print_access_mask(ULONG access) {
    int first = 1;
    printf("[");
    
    if (access & 0x00000001) { printf("%sFILE_READ_DATA", first ? "" : "|"); first = 0; }
    if (access & 0x00000002) { printf("%sFILE_WRITE_DATA", first ? "" : "|"); first = 0; }
    if (access & 0x00000004) { printf("%sFILE_APPEND_DATA", first ? "" : "|"); first = 0; }
    if (access & 0x00000008) { printf("%sFILE_READ_EA", first ? "" : "|"); first = 0; }
    if (access & 0x00000010) { printf("%sFILE_WRITE_EA", first ? "" : "|"); first = 0; }
    if (access & 0x00000020) { printf("%sFILE_EXECUTE", first ? "" : "|"); first = 0; }
    if (access & 0x00000040) { printf("%sFILE_DELETE_CHILD", first ? "" : "|"); first = 0; }
    if (access & 0x00000080) { printf("%sFILE_READ_ATTRIBUTES", first ? "" : "|"); first = 0; }
    if (access & 0x00000100) { printf("%sFILE_WRITE_ATTRIBUTES", first ? "" : "|"); first = 0; }
    if (access & 0x00010000) { printf("%sDELETE", first ? "" : "|"); first = 0; }
    if (access & 0x00020000) { printf("%sREAD_CONTROL", first ? "" : "|"); first = 0; }
    if (access & 0x00040000) { printf("%sWRITE_DAC", first ? "" : "|"); first = 0; }
    if (access & 0x00080000) { printf("%sWRITE_OWNER", first ? "" : "|"); first = 0; }
    if (access & 0x00100000) { printf("%sSYNCHRONIZE", first ? "" : "|"); first = 0; }
    
    if (first) printf("0x%08lX", access);
    printf("]");
}

const char* get_file_type(const wchar_t* path) {
    if (!path) return "FILE_TYPE_UNKNOWN";
    DWORD attrs = GetFileAttributesW(path);
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        return "FILE_TYPE_DIRECTORY";
    }
    return "FILE_TYPE_DISK";
}

int count_unique_pids(ProcessLockInfo* results, int count) {
    int unique = 0;
    DWORD lastPid = 0;
    
    for (int i = 0; i < count; i++) {
        if (results[i].pid != lastPid) {
            unique++;
            lastPid = results[i].pid;
        }
    }
    return unique;
}

void print_usage(const char* progname) {
    printf("Handle2 - file/folder lock scanner\n");
    printf("Usage: %s --path <path> [--json] [--debug] [--about]\n", progname);
    printf("\n");
    printf("Options:\n");
    printf("  --path <path>   File or folder to scan\n");
    printf("  --json          Output in JSON format\n");
    printf("  --debug         Show debug info (ObjectTypeIndex)\n");
    printf("  --about         Show information\n");
    printf("  -h, --help      Show this help\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s --path C:\\Windows\\System32\\notepad.exe\n", progname);
    printf("  %s --path C:\\Windows\\Temp\\ --json\n", progname);
    printf("  %s --path C:\\Users\\ --debug\n", progname);
}

void print_about(void) {
    printf("\n");
    printf("If this tool is useful to you and you want to support its author,\n");
    printf("you can send a donation via TRC-20 USDT/TRX:\n");
    printf("TTjnMhCcus7cibpAyx7PqaiQPuu4L6NV1a\n");
    printf("\n");
    printf("(c) 2026 playtester\n");
}

int main(int argc, char* argv[]) {
    setlocale(LC_ALL, "");
    
    const wchar_t* dllPaths[] = {
        L"Release/libhandle2.dll",
        L"./Release/libhandle2.dll",
        L"libhandle2.dll",
        L"./libhandle2.dll",
        NULL
    };
    
    HMODULE hDll = NULL;
    for (int i = 0; dllPaths[i]; i++) {
        hDll = LoadLibraryW(dllPaths[i]);
        if (hDll) break;
    }
    
    if (!hDll) {
        printf("Failed to load libhandle2.dll\n");
        return 1;
    }
    
    InitDefaultOptionsFunc InitDefaultOptions = (InitDefaultOptionsFunc)GetProcAddress(hDll, "InitDefaultOptions");
    ScanFolderFunc ScanFolder = (ScanFolderFunc)GetProcAddress(hDll, "ScanFolder");
    ScanFileFunc ScanFile = (ScanFileFunc)GetProcAddress(hDll, "ScanFile");
    GetScannerVersionFunc GetScannerVersion = (GetScannerVersionFunc)GetProcAddress(hDll, "GetScannerVersion");
    
    if (!InitDefaultOptions || !ScanFolder || !ScanFile || !GetScannerVersion) {
        printf("Failed to get functions from DLL\n");
        FreeLibrary(hDll);
        return 1;
    }
    
    const wchar_t* targetPath = NULL;
    BOOL jsonOutput = FALSE;
    BOOL debugOutput = FALSE;
    BOOL aboutOutput = FALSE;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            FreeLibrary(hDll);
            return 0;
        }
        else if (strcmp(argv[i], "--about") == 0) {
            aboutOutput = TRUE;
        }
        else if (strcmp(argv[i], "--json") == 0) {
            jsonOutput = TRUE;
        }
        else if (strcmp(argv[i], "--debug") == 0) {
            debugOutput = TRUE;
        }
        else if (strcmp(argv[i], "--path") == 0 && i + 1 < argc) {
            int len = MultiByteToWideChar(CP_UTF8, 0, argv[++i], -1, NULL, 0);
            wchar_t* wpath = (wchar_t*)malloc(len * sizeof(wchar_t));
            MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, wpath, len);
            targetPath = wpath;
        }
    }
    
    if (aboutOutput) {
        print_about();
        FreeLibrary(hDll);
        return 0;
    }
    
    if (!targetPath) {
        print_usage(argv[0]);
        FreeLibrary(hDll);
        return 1;
    }
    
    DWORD attrs = GetFileAttributesW(targetPath);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        wprintf(L"Error: Path does not exist: %ls\n", targetPath);
        free((void*)targetPath);
        FreeLibrary(hDll);
        return 1;
    }
    
    BOOL isDirectory = (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
    printf("Scanner version: %s\n\n", GetScannerVersion());
    
    ScanOptions opts;
    InitDefaultOptions(&opts);
    opts.includeModules = FALSE;
    opts.includeHandleTypes = TRUE;
    opts.timeoutMs = 50;
    opts.maxResults = 10000;
    
    int count = 0;
    ProcessLockInfo* results = NULL;
    
    if (isDirectory) {
        results = ScanFolder(targetPath, &count, &opts);
    } else {
        results = ScanFile(targetPath, &count, &opts);
    }
    
    if (!results || count == 0) {
        if (jsonOutput) {
            printf("{\n");
            printf("  \"Statistics\": {\n");
            printf("    \"UniqueProcesses\": 0,\n");
            printf("    \"TotalLocks\": 0\n");
            printf("  },\n");
            printf("  \"Results\": []\n");
            printf("}\n");
        } else {
            printf("\n=== RESULTS ===\n");
            printf("No processes found locking this path.\n");
        }
        free((void*)targetPath);
        FreeLibrary(hDll);
        return 0;
    }
    
    int uniquePids = count_unique_pids(results, count);
    
    if (jsonOutput) {
        printf("{\n");
        printf("  \"Statistics\": {\n");
        printf("    \"UniqueProcesses\": %d,\n", uniquePids);
        printf("    \"TotalLocks\": %d\n", count);
        printf("  },\n");
        printf("  \"Results\": [\n");
        
        for (int i = 0; i < count; i++) {
            printf("    {\n");
            printf("      \"Pid\": %lu,\n", results[i].pid);
            
            printf("      \"ProcessExecutablePath\": ");
            print_json_string(results[i].processPath);
            printf(",\n");
            
            printf("      \"UserName\": ");
            print_json_string(results[i].userName);
            printf(",\n");
            
            printf("      \"DomainName\": ");
            print_json_string(results[i].domainName);
            printf(",\n");
            
            printf("      \"Handles\": [\n");
            printf("        {\n");
            printf("          \"HandleType\": ");
            print_json_string(results[i].handleType ? results[i].handleType : L"File");
            printf(",\n");
            
            printf("          \"FileType\": \"%s\",\n", get_file_type(results[i].filePath));
            
            printf("          \"FullNameIfItIsAFileOrAFolder\": ");
            print_json_string(results[i].filePath);
            printf(",\n");
            
            printf("          \"GrantedAccess\": %lu,\n", results[i].grantedAccess);
            printf("          \"Attributes\": %lu,\n", results[i].attributes);
            printf("          \"AddressInTheKernelMemory\": %llu,\n", (unsigned long long)results[i].kernelAddress);
            if (debugOutput) {
                printf(",         \"ObjectTypeIndex\": %d,\n", results[i].objectTypeIndex);
                }
            printf("        }\n");
            printf("      ],\n");
            
            printf("      \"ModuleNames\": []\n");
    printf("    }%s\n", (i < count - 1) ? "," : "");
}
printf("  ]\n");
printf("}\n");
        
    } else {
        printf("\n=== RESULTS ===\n");
        printf("Unique processes: %d\n", uniquePids);
        printf("Total locks: %d\n\n", count);
        
        for (int i = 0; i < count; i++) {
            printf("[%lu] %ls (%ls\\%ls)\n", 
                   results[i].pid,
                   results[i].processPath ? results[i].processPath : L"<unknown>",
                   results[i].domainName,
                   results[i].userName);
            
            printf("  Path: %ls\n", results[i].filePath);
            printf("  Access: ");
            print_access_mask(results[i].grantedAccess);
            
            if (debugOutput) {
                printf("\n  ObjectTypeIndex: %d", results[i].objectTypeIndex);
            }
            printf("\n\n");
        }
        
        if (debugOutput) {
            printf("=== COLLECTED OBJECT TYPE INDICES ===\n");
            int indices[256] = {0};
            for (int i = 0; i < count; i++) {
                if (results[i].objectTypeIndex > 0 && results[i].objectTypeIndex < 256) {
                    indices[results[i].objectTypeIndex]++;
                }
            }
            for (int i = 0; i < 256; i++) {
                if (indices[i] > 0) {
                    printf("  Index %d (0x%02X): %d times\n", i, i, indices[i]);
                }
            }
        }
    }
    
    free((void*)targetPath);
    FreeLibrary(hDll);
    
    return 0;
}