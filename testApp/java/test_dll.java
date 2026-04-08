// test_dll.java - Universal Java wrapper for libhandle2.dll (32/64-bit auto-detect)
// Compile: javac -encoding UTF-8 -cp "jna-5.14.0.jar;." test_dll.java
// Run: java -cp "jna-5.14.0.jar;." test_dll --help
//
// Tested with JDK 1.8.0 (Java 8)

import com.sun.jna.*;
import com.sun.jna.win32.StdCallLibrary;
import com.sun.jna.ptr.IntByReference;
import java.io.File;
import java.nio.charset.StandardCharsets;

public class test_dll {
    
    public interface LibHandle2 extends StdCallLibrary {
        
        public static class ScanOptions extends Structure {
            public int includeModules;
            public int includeHandleTypes;
            public int timeoutMs;
            public int maxResults;
            
            @Override
            protected java.util.List<String> getFieldOrder() {
                return java.util.Arrays.asList("includeModules", "includeHandleTypes", "timeoutMs", "maxResults");
            }
        }
        
        void InitDefaultOptions(ScanOptions options);
        Pointer ScanFolder(WString folderPath, IntByReference resultCount, ScanOptions options);
        Pointer ScanFile(WString filePath, IntByReference resultCount, ScanOptions options);
        String GetScannerVersion();
    }
    
    static class ProcessLockInfo {
        int pid;
        String processPath;
        String filePath;
        String userName;
        String domainName;
        int grantedAccess;
        String handleType;
        long kernelAddress;
        int attributes;
        int objectTypeIndex;
    }
    
    // Determine JVM architecture via system property
    private static final boolean IS_64BIT = "64".equals(System.getProperty("sun.arch.data.model"));
    
    // Offsets for 32 and 64 bit
    private static final int STRUCT_SIZE;
    private static final int OFF_PROCESS_PATH;
    private static final int OFF_FILE_PATH;
    private static final int OFF_USER_NAME;
    private static final int OFF_DOMAIN_NAME;
    private static final int OFF_GRANTED_ACCESS;
    private static final int OFF_HANDLE_TYPE;
    private static final int OFF_KERNEL_ADDRESS;
    private static final int OFF_ATTRIBUTES;
    private static final int OFF_OBJECT_TYPE_INDEX;
    
    static {
        if (IS_64BIT) {
            // 64-bit offsets
            STRUCT_SIZE = 1088;
            OFF_PROCESS_PATH = 8;
            OFF_FILE_PATH = 16;
            OFF_USER_NAME = 24;
            OFF_DOMAIN_NAME = 536;
            OFF_GRANTED_ACCESS = 1060;
            OFF_HANDLE_TYPE = 1064;
            OFF_KERNEL_ADDRESS = 1072;
            OFF_ATTRIBUTES = 1080;
            OFF_OBJECT_TYPE_INDEX = 1084;
        } else {
            // 32-bit offsets
            STRUCT_SIZE = 1064;
            OFF_PROCESS_PATH = 4;
            OFF_FILE_PATH = 8;
            OFF_USER_NAME = 12;
            OFF_DOMAIN_NAME = 524;
            OFF_GRANTED_ACCESS = 1044;
            OFF_HANDLE_TYPE = 1048;
            OFF_KERNEL_ADDRESS = 1052;
            OFF_ATTRIBUTES = 1056;
            OFF_OBJECT_TYPE_INDEX = 1060;
        }
    }
    
    private static String safeGetWideString(Pointer ptr) {
        if (ptr == null || Pointer.nativeValue(ptr) == 0) return "<unknown>";
        try {
            String s = ptr.getWideString(0);
            return (s != null && !s.isEmpty()) ? s : "<unknown>";
        } catch (Exception e) {
            return "<unknown>";
        }
    }
    
    private static String safeGetDirectString(Pointer p, int offset, int maxBytes) {
        try {
            byte[] bytes = new byte[maxBytes];
            p.read(offset, bytes, 0, maxBytes);
            // Find null terminator
            int len = 0;
            for (int i = 0; i < maxBytes; i += 2) {
                if (i + 1 < maxBytes && bytes[i] == 0 && bytes[i+1] == 0) {
                    break;
                }
                len = i + 2;
            }
            return new String(bytes, 0, len, StandardCharsets.UTF_16LE).trim();
        } catch (Exception e) {
            return "";
        }
    }
    
    private static ProcessLockInfo readProcessLockInfo(Pointer p) {
        ProcessLockInfo info = new ProcessLockInfo();
        
        // PID (same for both architectures)
        info.pid = p.getInt(0);
        
        // Read pointers for processPath and filePath
        Pointer processPathPtr = p.getPointer(OFF_PROCESS_PATH);
        Pointer filePathPtr = p.getPointer(OFF_FILE_PATH);
        
        info.processPath = safeGetWideString(processPathPtr);
        info.filePath = safeGetWideString(filePathPtr);
        
        // Read direct Unicode strings
        info.userName = safeGetDirectString(p, OFF_USER_NAME, 512);
        info.domainName = safeGetDirectString(p, OFF_DOMAIN_NAME, 512);
        
        // Read other fields
        info.grantedAccess = p.getInt(OFF_GRANTED_ACCESS);
        
        Pointer handleTypePtr = p.getPointer(OFF_HANDLE_TYPE);
        info.handleType = safeGetWideString(handleTypePtr);
        if (info.handleType == null || info.handleType.isEmpty()) info.handleType = "File";
        
        // kernelAddress: 32-bit uses int, 64-bit uses long
        if (IS_64BIT) {
            info.kernelAddress = p.getLong(OFF_KERNEL_ADDRESS);
        } else {
            info.kernelAddress = p.getInt(OFF_KERNEL_ADDRESS) & 0xFFFFFFFFL;
        }
        
        info.attributes = p.getInt(OFF_ATTRIBUTES);
        info.objectTypeIndex = p.getShort(OFF_OBJECT_TYPE_INDEX) & 0xFFFF;
        
        return info;
    }
    
    private static void printAccessMask(int access) {
        int first = 1;
        System.out.print("[");
        
        if ((access & 0x00000001) != 0) { System.out.print((first == 0 ? "|" : "") + "FILE_READ_DATA"); first = 0; }
        if ((access & 0x00000002) != 0) { System.out.print((first == 0 ? "|" : "") + "FILE_WRITE_DATA"); first = 0; }
        if ((access & 0x00000004) != 0) { System.out.print((first == 0 ? "|" : "") + "FILE_APPEND_DATA"); first = 0; }
        if ((access & 0x00000008) != 0) { System.out.print((first == 0 ? "|" : "") + "FILE_READ_EA"); first = 0; }
        if ((access & 0x00000010) != 0) { System.out.print((first == 0 ? "|" : "") + "FILE_WRITE_EA"); first = 0; }
        if ((access & 0x00000020) != 0) { System.out.print((first == 0 ? "|" : "") + "FILE_EXECUTE"); first = 0; }
        if ((access & 0x00000040) != 0) { System.out.print((first == 0 ? "|" : "") + "FILE_DELETE_CHILD"); first = 0; }
        if ((access & 0x00000080) != 0) { System.out.print((first == 0 ? "|" : "") + "FILE_READ_ATTRIBUTES"); first = 0; }
        if ((access & 0x00000100) != 0) { System.out.print((first == 0 ? "|" : "") + "FILE_WRITE_ATTRIBUTES"); first = 0; }
        if ((access & 0x00010000) != 0) { System.out.print((first == 0 ? "|" : "") + "DELETE"); first = 0; }
        if ((access & 0x00020000) != 0) { System.out.print((first == 0 ? "|" : "") + "READ_CONTROL"); first = 0; }
        if ((access & 0x00040000) != 0) { System.out.print((first == 0 ? "|" : "") + "WRITE_DAC"); first = 0; }
        if ((access & 0x00080000) != 0) { System.out.print((first == 0 ? "|" : "") + "WRITE_OWNER"); first = 0; }
        if ((access & 0x00100000) != 0) { System.out.print((first == 0 ? "|" : "") + "SYNCHRONIZE"); first = 0; }
        
        if (first == 1) System.out.printf("0x%08X", access);
        System.out.print("]");
    }
    
    private static String getFileType(String path) {
        if (path == null) return "FILE_TYPE_UNKNOWN";
        File f = new File(path);
        if (f.isDirectory()) return "FILE_TYPE_DIRECTORY";
        return "FILE_TYPE_DISK";
    }
    
    private static void printJsonString(String str) {
        if (str == null) {
            System.out.print("\"\"");
            return;
        }
        System.out.print("\"");
        for (char c : str.toCharArray()) {
            switch (c) {
                case '\\': System.out.print("\\\\"); break;
                case '"': System.out.print("\\\""); break;
                case '\n': System.out.print("\\n"); break;
                case '\r': System.out.print("\\r"); break;
                case '\t': System.out.print("\\t"); break;
                default:
                    if (c < 0x20) {
                        System.out.printf("\\u%04X", (int)c);
                    } else {
                        System.out.print(c);
                    }
            }
        }
        System.out.print("\"");
    }
    
    private static int countUniquePids(ProcessLockInfo[] results, int count) {
        int unique = 0;
        int lastPid = -1;
        for (int i = 0; i < count; i++) {
            if (results[i].pid != lastPid) {
                unique++;
                lastPid = results[i].pid;
            }
        }
        return unique;
    }
    
    public static void main(String[] args) {
        // Print architecture info
        System.out.println("JVM Architecture: " + (IS_64BIT ? "64-bit" : "32-bit"));
        System.out.println("Structure size: " + STRUCT_SIZE + " bytes");
        System.out.println();
        
        // Parse arguments
        String targetPath = null;
        boolean jsonOutput = false;
        boolean debugOutput = false;
        boolean aboutOutput = false;
        
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (arg.equals("--help") || arg.equals("-h")) {
                System.out.println("Handle2 - file/folder lock scanner");
                System.out.println("Usage: java test_dll --path <path> [--json] [--debug] [--about]");
                System.out.println();
                System.out.println("Options:");
                System.out.println("  --path <path>   File or folder to scan");
                System.out.println("  --json          Output in JSON format");
                System.out.println("  --debug         Show debug info (ObjectTypeIndex)");
                System.out.println("  --about         Show information");
                System.out.println("  -h, --help      Show this help");
                System.out.println();
                System.out.println("Examples:");
                System.out.println("  java test_dll --path C:\\Windows\\System32\\notepad.exe");
                System.out.println("  java test_dll --path C:\\Windows\\Temp\\ --json");
                System.out.println("  java test_dll --path C:\\Users\\ --debug");
                return;
            } else if (arg.equals("--about")) {
                aboutOutput = true;
            } else if (arg.equals("--json")) {
                jsonOutput = true;
            } else if (arg.equals("--debug")) {
                debugOutput = true;
            } else if (arg.equals("--path") && i + 1 < args.length) {
                targetPath = args[++i];
            }
        }
        
        if (aboutOutput) {
            System.out.println();
            System.out.println("If this tool is useful to you and you want to support its author,");
            System.out.println("you can send a donation via TRC-20 USDT/TRX:");
            System.out.println("TTjnMhCcus7cibpAyx7PqaiQPuu4L6NV1a");
            System.out.println();
            System.out.println("(c) 2026 playtester");
            return;
        }
        
        if (targetPath == null) {
            System.out.println("Error: --path argument is required");
            return;
        }
        
        File pathFile = new File(targetPath);
        if (!pathFile.exists()) {
            System.out.println("Error: Path does not exist: " + targetPath);
            return;
        }
        
        // Load DLL
        LibHandle2 dll;
        try {
            dll = Native.load("libhandle2.dll", LibHandle2.class);
        } catch (UnsatisfiedLinkError e) {
            System.out.println("Failed to load libhandle2.dll: " + e.getMessage());
            System.out.println("Make sure the DLL architecture matches JVM architecture (" + (IS_64BIT ? "64-bit" : "32-bit") + ")");
            return;
        }
        
        // Get version
        try {
            String version = dll.GetScannerVersion();
            System.out.println("Scanner version: " + version + "\n");
        } catch (Exception e) {
            System.out.println("Scanner version: unknown\n");
        }
        
        // Setup options
        LibHandle2.ScanOptions opts = new LibHandle2.ScanOptions();
        dll.InitDefaultOptions(opts);
        opts.includeModules = 0;
        opts.includeHandleTypes = 1;
        opts.timeoutMs = 50;
        opts.maxResults = 10000;
        
        // Scan
        IntByReference count = new IntByReference(0);
        Pointer resultsPtr;
        boolean isDirectory = pathFile.isDirectory();
        
        if (isDirectory) {
            resultsPtr = dll.ScanFolder(new WString(targetPath), count, opts);
        } else {
            resultsPtr = dll.ScanFile(new WString(targetPath), count, opts);
        }
        
        if (resultsPtr == null || count.getValue() == 0) {
            if (jsonOutput) {
                System.out.println("{");
                System.out.println("  \"Statistics\": {");
                System.out.println("    \"UniqueProcesses\": 0,");
                System.out.println("    \"TotalLocks\": 0");
                System.out.println("  },");
                System.out.println("  \"Results\": []");
                System.out.println("}");
            } else {
                System.out.println("\n=== RESULTS ===");
                System.out.println("No processes found locking this path.");
            }
            return;
        }
        
        // Read all results
        ProcessLockInfo[] results = new ProcessLockInfo[count.getValue()];
        
        for (int i = 0; i < count.getValue(); i++) {
            Pointer p = resultsPtr.share((long)i * STRUCT_SIZE);
            results[i] = readProcessLockInfo(p);
        }
        
        int uniquePids = countUniquePids(results, count.getValue());
        
        if (jsonOutput) {
            System.out.println("{");
            System.out.println("  \"Statistics\": {");
            System.out.println("    \"UniqueProcesses\": " + uniquePids + ",");
            System.out.println("    \"TotalLocks\": " + count.getValue());
            System.out.println("  },");
            System.out.println("  \"Results\": [");
            
            for (int i = 0; i < count.getValue(); i++) {
                ProcessLockInfo item = results[i];
                System.out.println("    {");
                System.out.println("      \"Pid\": " + item.pid + ",");
                System.out.print("      \"ProcessExecutablePath\": ");
                printJsonString(item.processPath);
                System.out.println(",");
                System.out.print("      \"UserName\": ");
                printJsonString(item.userName);
                System.out.println(",");
                System.out.print("      \"DomainName\": ");
                printJsonString(item.domainName);
                System.out.println(",");
                System.out.println("      \"Handles\": [");
                System.out.println("        {");
                System.out.print("          \"HandleType\": ");
                printJsonString(item.handleType);
                System.out.println(",");
                System.out.println("          \"FileType\": \"" + getFileType(item.filePath) + "\",");
                System.out.print("          \"FullNameIfItIsAFileOrAFolder\": ");
                printJsonString(item.filePath);
                System.out.println(",");
                System.out.println("          \"GrantedAccess\": " + item.grantedAccess + ",");
                System.out.println("          \"Attributes\": " + item.attributes + ",");
                System.out.println("          \"AddressInTheKernelMemory\": " + item.kernelAddress);
                if (debugOutput) {
                    System.out.println("          \"ObjectTypeIndex\": " + item.objectTypeIndex);
                }
                System.out.println("        }");
                System.out.println("      ],");
                System.out.println("      \"ModuleNames\": []");
                System.out.print("    }");
                if (i < count.getValue() - 1) System.out.print(",");
                System.out.println();
            }
            System.out.println("  ]");
            System.out.println("}");
        } else {
            System.out.println("\n=== RESULTS ===");
            System.out.println("Unique processes: " + uniquePids);
            System.out.println("Total locks: " + count.getValue() + "\n");
            
            for (int i = 0; i < count.getValue(); i++) {
                ProcessLockInfo item = results[i];
                String processPath = (item.processPath != null && !item.processPath.isEmpty()) ? item.processPath : "<unknown>";
                System.out.printf("[%d] %s (%s\\%s)%n", 
                    item.pid, processPath, item.domainName, item.userName);
                System.out.println("  Path: " + item.filePath);
                System.out.print("  Access: ");
                printAccessMask(item.grantedAccess);
                if (debugOutput) {
                    System.out.println("\n  ObjectTypeIndex: " + item.objectTypeIndex);
                } else {
                    System.out.println();
                }
                System.out.println();
            }
            
            if (debugOutput) {
                System.out.println("=== COLLECTED OBJECT TYPE INDICES ===");
                int[] indices = new int[256];
                for (int i = 0; i < count.getValue(); i++) {
                    if (results[i].objectTypeIndex > 0 && results[i].objectTypeIndex < 256) {
                        indices[results[i].objectTypeIndex]++;
                    }
                }
                for (int i = 0; i < 256; i++) {
                    if (indices[i] > 0) {
                        System.out.printf("  Index %d (0x%02X): %d times%n", i, i, indices[i]);
                    }
                }
            }
        }
    }
}