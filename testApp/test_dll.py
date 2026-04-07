# test_dll.py - Python wrapper for libHandle2.dll
# Tested with Python 3.8.10+

import ctypes
from ctypes import wintypes
import json
import sys
import os
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')


def show_help():
    print("Handle2 - file/folder lock scanner")
    print("Usage: python test_dll.py --path <path> [--json] [--debug] [--about]")
    print()
    print("Options:")
    print("  --path <path>   File or folder to scan")
    print("  --json          Output in JSON format")
    print("  --debug         Show debug info (ObjectTypeIndex)")
    print("  --about         Show information")
    print("  -h, --help      Show this help")
    print()
    print("Examples:")
    print("  python test_dll.py --path C:\\Windows\\System32\\notepad.exe")
    print("  python test_dll.py --path C:\\Windows\\Temp\\ --json")
    print("  python test_dll.py --path C:\\Users\\ --debug")

def print_about():
    print()
    print("If this tool is useful to you and you want to support its author,")
    print("you can send a donation via TRC-20 USDT/TRX:")
    print("TTjnMhCcus7cibpAyx7PqaiQPuu4L6NV1a")
    print()
    print("(c) 2026 playtester")

def main():
    dll_paths = [
        "Release/libhandle2.dll",
        "./Release/libhandle2.dll",
        "libhandle2.dll",
        "./libhandle2.dll"
    ]
    
    dll = None
    for path in dll_paths:
        try:
            dll = ctypes.CDLL(path)
            break
        except OSError:
            continue
    
    if not dll:
        print("Failed to load libhandle2.dll")
        return 1
    
    # ScanOptions structure (updated - removed recursive and includeAccess)
    class ScanOptions(ctypes.Structure):
        _fields_ = [
            ("includeModules", ctypes.c_int),
            ("includeHandleTypes", ctypes.c_int),
            ("timeoutMs", ctypes.c_int),
            ("maxResults", ctypes.c_int),
        ]
    
    # ProcessLockInfo structure (added objectTypeIndex)
    class ProcessLockInfo(ctypes.Structure):
        _fields_ = [
            ("pid", wintypes.DWORD),
            ("processPath", ctypes.c_wchar_p),
            ("filePath", ctypes.c_wchar_p),
            ("userName", ctypes.c_wchar * 256),
            ("domainName", ctypes.c_wchar * 256),
            ("moduleNames", ctypes.POINTER(ctypes.c_wchar_p)),
            ("moduleCount", ctypes.c_int),
            ("grantedAccess", wintypes.ULONG),
            ("handleType", ctypes.c_wchar_p),
            ("kernelAddress", ctypes.c_ulonglong),
            ("attributes", wintypes.ULONG),
            ("objectTypeIndex", ctypes.c_ushort),
        ]
    
    InitDefaultOptions = dll.InitDefaultOptions
    InitDefaultOptions.argtypes = [ctypes.POINTER(ScanOptions)]
    InitDefaultOptions.restype = None
    
    ScanFolder = dll.ScanFolder
    ScanFolder.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ScanOptions)]
    ScanFolder.restype = ctypes.POINTER(ProcessLockInfo)
    
    ScanFile = dll.ScanFile
    ScanFile.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ScanOptions)]
    ScanFile.restype = ctypes.POINTER(ProcessLockInfo)
    
    GetScannerVersion = dll.GetScannerVersion
    GetScannerVersion.argtypes = []
    GetScannerVersion.restype = ctypes.c_char_p
    
    target_path = None
    json_output = False
    debug_output = False
    about_output = False
    
    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg in ["--help", "-h"]:
            show_help()
            return 0
        elif arg == "--about":
            about_output = True
        elif arg == "--json":
            json_output = True
        elif arg == "--debug":
            debug_output = True
        elif arg == "--path" and i + 1 < len(sys.argv):
            i += 1
            target_path = sys.argv[i]
        else:
            print()
            print(f"Unknown option: {arg}")
            print()
            show_help()
            return 1
        i += 1
    
    if about_output:
        print_about()
        return 0
    
    if not target_path:
        print()
        print("Error: --path argument is required")
        print()
        show_help()
        return 1
    
    if not os.path.exists(target_path):
        print()
        print(f"Error: Path does not exist: {target_path}")
        print()
        show_help()
        return 1
    
    is_directory = os.path.isdir(target_path)
    
    try:
        version = GetScannerVersion().decode('utf-8')
        print(f"Scanner version: {version}\n")
    except:
        print("Scanner version: unknown\n")
    
    opts = ScanOptions()
    InitDefaultOptions(ctypes.byref(opts))
    opts.includeModules = 0
    opts.includeHandleTypes = 1
    opts.timeoutMs = 50
    opts.maxResults = 10000
    
    count = ctypes.c_int(0)
    if is_directory:
        results = ScanFolder(target_path, ctypes.byref(count), ctypes.byref(opts))
    else:
        results = ScanFile(target_path, ctypes.byref(count), ctypes.byref(opts))
    
    if not results or count.value == 0:
        if json_output:
            print(json.dumps({
                "Statistics": {"UniqueProcesses": 0, "TotalLocks": 0},
                "Results": []
            }, indent=2, ensure_ascii=False))
        else:
            print("\n=== RESULTS ===")
            print("No processes found locking this path.")
        return 0
    
    # Count unique PIDs
    unique_pids = 0
    last_pid = 0
    for i in range(count.value):
        if results[i].pid != last_pid:
            unique_pids += 1
            last_pid = results[i].pid
    
    def get_file_type(path):
        if not path:
            return "FILE_TYPE_UNKNOWN"
        if os.path.isdir(path):
            return "FILE_TYPE_DIRECTORY"
        return "FILE_TYPE_DISK"
    
    def print_access_mask(access):
        flags = []
        if access & 0x00000001: flags.append("FILE_READ_DATA")
        if access & 0x00000002: flags.append("FILE_WRITE_DATA")
        if access & 0x00000004: flags.append("FILE_APPEND_DATA")
        if access & 0x00000008: flags.append("FILE_READ_EA")
        if access & 0x00000010: flags.append("FILE_WRITE_EA")
        if access & 0x00000020: flags.append("FILE_EXECUTE")
        if access & 0x00000040: flags.append("FILE_DELETE_CHILD")
        if access & 0x00000080: flags.append("FILE_READ_ATTRIBUTES")
        if access & 0x00000100: flags.append("FILE_WRITE_ATTRIBUTES")
        if access & 0x00010000: flags.append("DELETE")
        if access & 0x00020000: flags.append("READ_CONTROL")
        if access & 0x00040000: flags.append("WRITE_DAC")
        if access & 0x00080000: flags.append("WRITE_OWNER")
        if access & 0x00100000: flags.append("SYNCHRONIZE")
        
        if flags:
            return "[" + "|".join(flags) + "]"
        return f"[0x{access:08X}]"
    
    if json_output:
        output = {
            "Statistics": {
                "UniqueProcesses": unique_pids,
                "TotalLocks": count.value
            },
            "Results": []
        }
        
        for i in range(count.value):
            item = results[i]
            handle_entry = {
                "HandleType": item.handleType if item.handleType else "File",
                "FileType": get_file_type(item.filePath),
                "FullNameIfItIsAFileOrAFolder": item.filePath,
                "GrantedAccess": item.grantedAccess,
                "Attributes": item.attributes,
                "AddressInTheKernelMemory": item.kernelAddress
            }
            if debug_output:
                handle_entry["ObjectTypeIndex"] = item.objectTypeIndex
            
            output["Results"].append({
                "Pid": item.pid,
                "ProcessExecutablePath": item.processPath,
                "UserName": item.userName,
                "DomainName": item.domainName,
                "Handles": [handle_entry],
                "ModuleNames": []
            })
        
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        print("\n=== RESULTS ===")
        print(f"Unique processes: {unique_pids}")
        print(f"Total locks: {count.value}\n")
        
        for i in range(count.value):
            item = results[i]
            process_path = item.processPath if item.processPath else "<unknown>"
            print(f"[{item.pid}] {process_path} ({item.domainName}\\{item.userName})")
            print(f"  Path: {item.filePath}")
            print(f"  Access: {print_access_mask(item.grantedAccess)}")
            if debug_output:
                print(f"  ObjectTypeIndex: {item.objectTypeIndex}")
            print()
        
        if debug_output:
            print("=== COLLECTED OBJECT TYPE INDICES ===")
            indices = {}
            for i in range(count.value):
                idx = results[i].objectTypeIndex
                if idx > 0 and idx < 256:
                    indices[idx] = indices.get(idx, 0) + 1
            for idx, cnt in sorted(indices.items()):
                print(f"  Index {idx} (0x{idx:02X}): {cnt} times")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())