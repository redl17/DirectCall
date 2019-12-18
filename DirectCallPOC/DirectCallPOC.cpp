// DirectCallPOC.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>
#include<Windows.h>
#include <stdio.h>
#include "DirectCallPOC.h"

using namespace std;

#define NTSTATUS = status;

//Because MS makes string handling a nighmare :)
#undef  _UNICODE
#define _UNICODE
#undef  UNICODE
#define UNICODE

int main()
{
	//Alias NtCreateFile to our assembly code for this version of Windows 10
	NtCreateFile = &NtCreateFile10;
	
	//More string messy string hanling
	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlInitUnicodeString");

	WCHAR FileName[50] = L"C:\\Windows\\Temp\\test.bin";
	UNICODE_STRING uFileName;
	RtlInitUnicodeString(&uFileName, FileName);  //Finally a unicode string
	
	//Initialize the input variables for the call to CreateFile
	HANDLE hDumpFile = NULL;
	IO_STATUS_BLOCK IoStatusBlock;
	ZeroMemory(&IoStatusBlock, sizeof(IoStatusBlock));
	OBJECT_ATTRIBUTES FileObjectAttributes;
	InitializeObjectAttributes (&FileObjectAttributes, &uFileName, OBJ_CASE_INSENSITIVE	, NULL, NULL);

	
	
}


