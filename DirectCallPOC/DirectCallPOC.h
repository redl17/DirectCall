#pragma once
#include <Windows.h>


#define STATUS_SUCCESS 0
#define OBJ_CASE_INSENSITIVE 0x00000040
#define FILE_OVERWRITE_IF 0x00000005
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020

#define InitializeObjectAttributes( i, o, a, r, s ) {    \
      (i)->Length = sizeof( OBJECT_ATTRIBUTES );         \
      (i)->RootDirectory = r;                            \
      (i)->Attributes = a;                               \
      (i)->ObjectName = o;                               \
      (i)->SecurityDescriptor = s;                       \
      (i)->SecurityQualityOfService = NULL;              \
   }

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		NTSTATUS Status;
		PVOID Pointer;
	};
	ULONG Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef void (WINAPI* _RtlInitUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
	);


typedef struct _WIN_VER_INFO {
	WCHAR chOSMajorMinor[8];
	DWORD dwBuildNumber;
	UNICODE_STRING ProcName;
	HANDLE hTargetPID;
	LPCSTR lpApiCall;
	INT SystemCall;
} WIN_VER_INFO, *PWIN_VER_INFO;

typedef NTSTATUS(NTAPI *_RtlGetVersion)(
	LPOSVERSIONINFOEXW lpVersionInformation
	);


NTSTATUS(*NtCreateFile)(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	PVOID EaBuffer,
	ULONG EaLength
	);

EXTERN_C NTSTATUS NtCreateFile10(
	PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, 
	PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, 
	ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);

NTSTATUS(*ZwClose)(
	IN HANDLE KeyHandle
	);

