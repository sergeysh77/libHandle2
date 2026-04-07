**Description**  
Idea and most of the implementation are taken from the PolarGoose project: https://github.com/PolarGoose/Handle2  
libHandle2.dll library is designed to find processes that hold open files or folders in the Windows system. It allows you to determine which process is blocking a file/folder, with what access rights, and from which user.  

**Features**
- Find processes blocking a specified file
- Find processes blocking a specified folder (recursively, including all files inside)
- Get process information: PID, executable path, user
- Get file/folder access rights (Read, Write, Execute, etc.)
- Operation timeouts (protection against hangs)
- Caching of opened processes
- Handle filtering by "File" type index

**Exported Functions**

___InitDefaultOptions___ - Initializes the ScanOptions structure with default values.  
Parameters:  
options - pointer to ScanOptions structure  
Default values:  
includeModules = FALSE  
includeHandleTypes = TRUE  
timeoutMs = 20  
maxResults = 10000  

___ScanFolder___ - Scans a folder and returns all processes holding the folder itself or any files inside it (recursively).  
Parameters:  
folderPath - path to the folder (e.g., L"C:\\Windows\\Temp")  
resultCount - pointer to int where the number of found locks will be stored  
options - pointer to ScanOptions structure (can be NULL)  
Returns:  
Pointer to an array of ProcessLockInfo structures  
NULL on error  

___ScanFile___ - Scans a specific file and returns processes holding that file.  
Parameters:  
filePath - path to the file (e.g., L"C:\\Testfile.docx")  
resultCount - pointer to int where the number of found locks will be stored  
options - pointer to ScanOptions structure (can be NULL)  
Returns:  
Pointer to an array of ProcessLockInfo structures  
NULL on error  

___GetScannerVersion___ - Returns the library version.  
Returns:  
Version string (e.g., "1.0.0")  

___GetLastScannerError___ - Returns the last error that occurred during scanning.  
Returns:  
Error description string  

**Data Structures**

```c
typedef struct {
    BOOL includeModules;      // Include process module list (not fully implemented)
    BOOL includeHandleTypes;  // Include handle type in the result
    int timeoutMs;            // Operation timeout (ms), recommended 20-100
    int maxResults;           // Maximum number of results
} ScanOptions;

typedef struct {
    DWORD pid;                    // Process ID
    wchar_t* processPath;         // Path to the process executable file
    wchar_t* filePath;            // Path to the locked file/folder
    wchar_t userName[256];        // User name
    wchar_t domainName[256];      // Domain/computer name
    wchar_t** moduleNames;        // List of process modules (optional)
    int moduleCount;              // Number of modules
    ULONG grantedAccess;          // Access rights (bitmask)
    wchar_t* handleType;          // Object type (always "File")
    ULONG_PTR kernelAddress;      // Object address in kernel memory
    ULONG attributes;             // Handle attributes
    USHORT objectTypeIndex;       // Object type index (for debugging)
} ProcessLockInfo;
```

Requirements: Windows Vista / 7 / 8 / 10 / 11  
Privileges: Administrator privileges recommended (for accessing other processes)  
Architecture: x86 or x64 (DLL must match application architecture)  
