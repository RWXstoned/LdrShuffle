#pragma once
#include <windows.h>
#define MAX_ARGS 10
#define SLEEPTIME 15    // sleeptime in seconds



// ======================================== HEADERS ========================================  //

// ---- DATA_T structure used for data transmission when we execute calls via LDR structures tampering. This is were return value of call is stored
// so that it remains accessible
typedef struct _DATA_T {
    // LDR structures manipulation
    ULONG_PTR   runner;             // malicious entry point to execute
    ULONG_PTR   bakOriginalBase;    // backup of overwritten OriginalBase
    ULONG_PTR   bakEntryPoint;      // backup of overwritten EntryPoint
    HANDLE      event;              // event signalling that the Runner has executed
    // function call
    ULONG_PTR   ret;                // return value
    DWORD       createThread;       // run this API call in a new thread (required for wininet/winhttp)
    ULONG_PTR   function;           // Windows API to call
    DWORD       dwArgs;             // number of args
    ULONG_PTR   args[MAX_ARGS];     // array of args
} DATA_T, * PDATA_T;

PDATA_T GetPdataT(IN HMODULE);