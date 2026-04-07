// src/memory.c
#include "private.h"

void FreeScanResults(ProcessLockInfo* results, int count) {
    if (!results) return;
    
    for (int i = 0; i < count; i++) {
        if (results[i].processPath) free(results[i].processPath);
        if (results[i].filePath) free(results[i].filePath);
        if (results[i].handleType) free(results[i].handleType);
        if (results[i].moduleNames) {
            for (int j = 0; j < results[i].moduleCount; j++) {
                if (results[i].moduleNames[j]) free(results[i].moduleNames[j]);
            }
            free(results[i].moduleNames);
        }
    }
    
    free(results);
    CloseProcessCache();
    g_timeoutCount = 0;
}