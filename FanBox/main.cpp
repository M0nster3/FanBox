#include <windows.h>
#include <stdio.h>
#include <wbemcli.h >
#include <locale.h >
#include <Shlwapi.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <VersionHelpers.h>

#pragma comment(lib,"Shlwapi.lib")
#pragma comment(lib,"wbemuuid.lib")
//处理器数量
BOOL NumberOfProcessors()
{
#if defined (_WIN64)
	PULONG ulNumberProcessors = (PULONG)(__readgsqword(0x60) + 0xB8);

#elif defined(_WIN32)
	PULONG ulNumberProcessors = (PULONG)(__readfsdword(0x30) + 0x64);

#endif

	if (*ulNumberProcessors < 2) {
		return TRUE;
	}
		
	else
		return FALSE;
}


BOOL InitWMI(IWbemServices** pSvc, IWbemLocator** pLoc, const TCHAR* szNetworkResource)
{
	
	// Initialize COM.
	HRESULT hres;
	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres)) {
		printf("CoInitializeEx\n");
		return 0;
	}

	// Set general COM security levels
	hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
	if (FAILED(hres)) {
		printf("CoInitializeSecurity\n");
		CoUninitialize();
		return 0;
	}

	// Obtain the initial locator to WMI 
	hres = CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(pLoc));
	if (FAILED(hres)) {
		printf("CoCreateInstance\n");
		CoUninitialize();
		return 0;
	}

	BSTR strNetworkResource = SysAllocString(szNetworkResource);
	if (strNetworkResource) {

		// Connect to the root\cimv2 namespace 
		hres = (*pLoc)->ConnectServer(strNetworkResource, NULL, NULL, NULL, WBEM_FLAG_CONNECT_USE_MAX_WAIT, 0, 0, pSvc);
		if (FAILED(hres)) {
			SysFreeString(strNetworkResource);
			printf("ConnectServer");
			(*pLoc)->Release();
			CoUninitialize();
			return 0;
		}
		SysFreeString(strNetworkResource);
	}

	// Set security levels on the proxy -------------------------
	hres = CoSetProxyBlanket(*pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
	if (FAILED(hres))
	{
		printf("CoSetProxyBlanket");
		(*pSvc)->Release();
		(*pLoc)->Release();
		CoUninitialize();
		return 0;
	}

	return 1;
}

BOOL ExecWMIQuery(IWbemServices** pSvc, IWbemLocator** pLoc, IEnumWbemClassObject** pEnumerator, const TCHAR* szQuery)
{
	// Execute WMI query
	BSTR strQueryLanguage = SysAllocString(OLESTR("WQL"));
	BSTR strQuery = SysAllocString(szQuery);

	BOOL bQueryResult = TRUE;

	if (strQueryLanguage && strQuery) {

		HRESULT hres = (*pSvc)->ExecQuery(strQueryLanguage, strQuery,
			WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
			NULL, pEnumerator);

		if (FAILED(hres)) {
			bQueryResult = FALSE;
			printf("ExecQuery");
			(*pSvc)->Release();
			(*pLoc)->Release();
			CoUninitialize();
		}
	}
	if (strQueryLanguage) SysFreeString(strQueryLanguage);
	if (strQuery) SysFreeString(strQuery);

	return bQueryResult;
}
//wmic通过查看BIOS序列号

BOOL serial_number_bios_wmi()
{
	IWbemServices* pSvc = NULL;
	IWbemLocator* pLoc = NULL;
	IEnumWbemClassObject* pEnumerator = NULL;
	BOOL bStatus = FALSE;
	HRESULT hRes;
	BOOL bFound = FALSE;

	// Init WMI
	bStatus = InitWMI(&pSvc, &pLoc, L"ROOT\\CIMV2");

	if (bStatus)
	{
		// If success, execute the desired query
		bStatus = ExecWMIQuery(&pSvc, &pLoc, &pEnumerator, L"SELECT * FROM Win32_BIOS");
		if (bStatus)
		{
			// Get the data from the query
			IWbemClassObject* pclsObj = NULL;
			ULONG uReturn = 0;
			VARIANT vtProp;

			while (pEnumerator)
			{
				hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
				if (0 == uReturn)
					break;

				// Get the value of the Name property
				hRes = pclsObj->Get(L"SerialNumber", 0, &vtProp, 0, 0);
				if (SUCCEEDED(hRes)) {
					if (vtProp.vt == VT_BSTR) {

						// Do our comparison
						if (
							(StrStrI(vtProp.bstrVal, L"VMWare") != 0) ||
							(wcscmp(vtProp.bstrVal, L"0") == 0) || // VBox (serial is just "0")
							(StrStrI(vtProp.bstrVal, L"Xen") != 0) ||
							(StrStrI(vtProp.bstrVal, L"Virtual") != 0) ||
							(StrStrI(vtProp.bstrVal, L"A M I") != 0)
							)
						{
							VariantClear(&vtProp);
							pclsObj->Release();
							bFound = TRUE;
							break;
						}
					}
					VariantClear(&vtProp);
				}

				// release the current result object
				pclsObj->Release();
			}

			// Cleanup
			pSvc->Release();
			pLoc->Release();
			pEnumerator->Release();
			CoUninitialize();
		}
	}

	return bFound;
}
//使用wmic查看cpu核心数
BOOL number_cores_wmi()
{
	IWbemServices* pSvc = NULL;
	IWbemLocator* pLoc = NULL;
	IEnumWbemClassObject* pEnumerator = NULL;
	BOOL bStatus = FALSE;
	HRESULT hRes;
	BOOL bFound = FALSE;

	// Init WMI
	bStatus = InitWMI(&pSvc, &pLoc, L"ROOT\\CIMV2");
	if (bStatus)
	{
		// If success, execute the desired query
		bStatus = ExecWMIQuery(&pSvc, &pLoc, &pEnumerator, L"SELECT * FROM Win32_Processor");
		if (bStatus)
		{
			// Get the data from the query
			IWbemClassObject* pclsObj = NULL;
			ULONG uReturn = 0;
			VARIANT vtProp;

			// Iterate over our enumator
			while (pEnumerator)
			{
				hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
				if (0 == uReturn)
					break;

				// Get the value of the Name property
				hRes = pclsObj->Get(L"NumberOfCores", 0, &vtProp, 0, 0);
				if (SUCCEEDED(hRes)) {
					if (V_VT(&vtProp) != VT_NULL) {

						// Do our comparaison
						if (vtProp.uintVal < 2) {
							printf("%da\n", vtProp.uintVal);
							bFound = TRUE;
						}

						// release the current result object
						VariantClear(&vtProp);
					}
				}

				// release class object
				pclsObj->Release();

				// break from while
				if (bFound)
					break;
			}

			// Cleanup
			pEnumerator->Release();
			pSvc->Release();
			pLoc->Release();
			CoUninitialize();
		}
	}

	return bFound;
}
//使用wmic查看硬盘大小
BOOL disk_size_wmi()
{
	IWbemServices* pSvc = NULL;
	IWbemLocator* pLoc = NULL;
	IEnumWbemClassObject* pEnumerator = NULL;
	BOOL bStatus = FALSE;
	HRESULT hRes;
	BOOL bFound = FALSE;
	UINT64 minHardDiskSize = (80ULL * (1024ULL * (1024ULL * (1024ULL))));

	// Init WMI
	bStatus = InitWMI(&pSvc, &pLoc, L"ROOT\\CIMV2");
	if (bStatus)
	{
		// If success, execute the desired query
		bStatus = ExecWMIQuery(&pSvc, &pLoc, &pEnumerator, L"SELECT * FROM Win32_LogicalDisk");
		if (bStatus)
		{
			// Get the data from the query
			IWbemClassObject* pclsObj = NULL;
			ULONG uReturn = 0;
			VARIANT vtProp;

			// Iterate over our enumator
			while (pEnumerator)
			{
				hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
				if (0 == uReturn)
					break;

				// Get the value of the Name property
				hRes = pclsObj->Get(L"Size", 0, &vtProp, NULL, 0);
				if (SUCCEEDED(hRes)) {
					if (V_VT(&vtProp) != VT_NULL)
					{
						// convert disk size string to bytes
						errno = 0;
						unsigned long long diskSizeBytes = _wcstoui64_l(vtProp.bstrVal, NULL, 10, _get_current_locale());
						// do the check only if we successfuly got the disk size
						if (errno == 0)
						{
							// Do our comparison
							if (diskSizeBytes < minHardDiskSize) { // Less than 80GB
								printf("%d\n", diskSizeBytes);
								bFound = TRUE;
							}
						}

						// release the current result object
						VariantClear(&vtProp);
					}
				}

				// release class object
				pclsObj->Release();

				// break from while
				if (bFound)
					break;
			}

			// Cleanup
			pEnumerator->Release();
			pSvc->Release();
			pLoc->Release();
			CoUninitialize();
		}
	}

	return bFound;
}

//检查鼠标移动
BOOL mouse_movement() {

	POINT positionA ;
	POINT positionB ;

	/* Retrieve the position of the mouse cursor, in screen coordinates */
	GetCursorPos(&positionA);

	/* Wait a moment */
	Sleep(3000);

	/* Retrieve the poition gain */
	GetCursorPos(&positionB);

	if ((positionA.x == positionB.x) && (positionA.y == positionB.y))
	{
		printf("不移动");/* Probably a sandbox, because mouse position did not change. */
		return TRUE;
	}
	else
	{
		printf("移动");
		return FALSE;
	}
		
}
//检查内存空间
BOOL memory_space()
{
	DWORDLONG ullMinRam = (1024LL * (1024LL * (1024LL * 1LL))); // 1GB
	printf("%d\n", ullMinRam);
	MEMORYSTATUSEX statex;

	statex.dwLength = sizeof(statex);
	GlobalMemoryStatusEx(&statex);
	printf("%d", statex.ullTotalPhys);
	return (statex.ullTotalPhys < ullMinRam) ? TRUE : FALSE;
}
//检测时间是否加速（谨慎使用由于检测时间较长1分钟）
BOOL accelerated_sleep()
{
	DWORD dwStart = 0, dwEnd = 0, dwDiff = 0;
	DWORD dwMillisecondsToSleep = 60 * 1000;

	/* Retrieves the number of milliseconds that have elapsed since the system was started */
	dwStart = GetTickCount();

	/* Let's sleep 1 minute so Sandbox is interested to patch that */
	Sleep(dwMillisecondsToSleep);

	/* Do it again */
	dwEnd = GetTickCount();

	/* If the Sleep function was patched*/
	dwDiff = dwEnd - dwStart;
	if (dwDiff > dwMillisecondsToSleep - 1000) // substracted 1s just to be sure
		return FALSE;
	else
		return TRUE;
}

BOOL get_services(_In_ SC_HANDLE hServiceManager, _In_ DWORD serviceType, _Out_ ENUM_SERVICE_STATUS_PROCESS** servicesBuffer, _Out_ DWORD* serviceCount)
{
	DWORD serviceBufferSize = 1024 * sizeof(ENUM_SERVICE_STATUS_PROCESS);
	ENUM_SERVICE_STATUS_PROCESS* services = static_cast<ENUM_SERVICE_STATUS_PROCESS*>(malloc(serviceBufferSize));

	if (serviceCount) //assume failure
		*serviceCount = 0;

	if (services) {

		SecureZeroMemory(services, serviceBufferSize);

		DWORD remainderBufferSize = 0;
		DWORD resumeHandle = 0;
		if (EnumServicesStatusEx(hServiceManager, SC_ENUM_PROCESS_INFO, serviceType, SERVICE_STATE_ALL, (LPBYTE)services, serviceBufferSize, &remainderBufferSize, serviceCount, &resumeHandle, NULL) != 0)
		{
			// success and we enumerated all the services
			*servicesBuffer = services;
			return TRUE;
		}

		DWORD lastError = GetLastError();
		if (lastError == ERROR_MORE_DATA)
		{
			// we didn't get all the services, so we'll just re-enumerate all to make things easy
			serviceBufferSize += remainderBufferSize;

			ENUM_SERVICE_STATUS_PROCESS* tmp;

			tmp = static_cast<ENUM_SERVICE_STATUS_PROCESS*>(realloc(services, serviceBufferSize));
			if (tmp) {
				services = tmp;
				SecureZeroMemory(services, serviceBufferSize);
				if (EnumServicesStatusEx(hServiceManager, SC_ENUM_PROCESS_INFO, serviceType, SERVICE_STATE_ALL, (LPBYTE)services, serviceBufferSize, &remainderBufferSize, serviceCount, NULL, NULL) != 0)
				{
					*servicesBuffer = services;
					return TRUE;
				}
			}
		}
		else
		{
			printf("ERROR: %u\n", lastError);
		}

		free(services);

	}
	return FALSE;
}

//检测VMWARE
BOOL VMDriverServices()
{
	const int KnownServiceCount = 13;
	const TCHAR* KnownVMServices[KnownServiceCount] = {
		L"VBoxWddm",
		L"VBoxSF", //VirtualBox Shared Folders
		L"VBoxMouse", //VirtualBox Guest Mouse
		L"VBoxGuest", //VirtualBox Guest Driver
		L"vmci", //VMWare VMCI Bus Driver
		L"vmhgfs", //VMWare Host Guest Control Redirector
		L"vmmouse",
		L"vmmemctl", //VMWare Guest Memory Controller Driver
		L"vmusb",
		L"vmusbmouse",
		L"vmx_svga",
		L"vmxnet",
		L"vmx86"
	};

	SC_HANDLE hSCM = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
	if (hSCM != NULL)
	{
		ENUM_SERVICE_STATUS_PROCESS* services = NULL;
		DWORD serviceCount = 0;
		if (get_services(hSCM, SERVICE_DRIVER, &services, &serviceCount))
		{
			bool ok = true;

			for (DWORD i = 0; i < serviceCount; i++)
			{
				for (int s = 0; s < KnownServiceCount; s++)
				{
					if (StrCmpIW(services[i].lpServiceName, KnownVMServices[s]) == 0)
					{
						wprintf(L"%s", KnownVMServices[s]);
						ok = false;
						break;
					}
				}
			}
			free(services);

			if (ok)
			{
				CloseServiceHandle(hSCM);
				return FALSE;
			}

		}
		else
		{
			printf("Failed to get services list.\n");
		}
		CloseServiceHandle(hSCM);
	}
	else
	{
		printf("Failed to get SCM handle.\n");
	}

	return TRUE;
}

BOOL Is_RegKeyValueExists(HKEY hKey, const TCHAR* lpSubKey, const TCHAR* lpValueName, const TCHAR* search_str)
{
	HKEY hkResult = NULL;
	TCHAR lpData[1024] = { 0 };
	DWORD cbData = MAX_PATH;

	if (RegOpenKeyEx(hKey, lpSubKey, NULL, KEY_READ, &hkResult) == ERROR_SUCCESS)
	{
		if (RegQueryValueEx(hkResult, lpValueName, NULL, NULL, (LPBYTE)lpData, &cbData) == ERROR_SUCCESS)
		{
			if (StrStrI((PCTSTR)lpData, search_str) != NULL)
			{
				RegCloseKey(hkResult);
				return TRUE;
			}
		}
		RegCloseKey(hkResult);
	}
	return FALSE;

}
//检测注册表HKLM\System\CurrentControlSet\Services\Disk\Enum
BOOL registry_services_disk_enum()
{
	HKEY hkResult = NULL;
	const TCHAR* diskEnumKey = L"System\\CurrentControlSet\\Services\\Disk\\Enum";
	DWORD diskCount = 0;
	DWORD cbData = sizeof(diskCount);
	const TCHAR* szChecks[] = {
		 L"qemu",
		 L"virtio",
		 L"vmware",
		 L"vbox",
		 L"xen",
		 L"VMW",
		 L"Virtual",

	};
	WORD dwChecksLength = sizeof(szChecks) / sizeof(szChecks[0]);
	BOOL bFound = FALSE;


	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, diskEnumKey, NULL, KEY_READ, &hkResult) == ERROR_SUCCESS)
	{
		if (RegQueryValueEx(hkResult, L"Count", NULL, NULL, (LPBYTE)&diskCount, &cbData) != ERROR_SUCCESS)
		{
			RegCloseKey(hkResult);
			return bFound;
		}
		RegCloseKey(hkResult);
	}

	for (unsigned int i = 0; i < diskCount; i++) {
		TCHAR subkey[11];

		swprintf_s(subkey, sizeof(subkey) / sizeof(subkey[0]), L"%d", i);

		for (unsigned int j = 0; j < dwChecksLength; j++) {
			//_tprintf(L"Checking %s %s for %s (%d)\n"), diskEnumKey, subkey, szChecks[j], diskCount);
			wprintf(L"%s\n", diskEnumKey);
			if (Is_RegKeyValueExists(HKEY_LOCAL_MACHINE, diskEnumKey, subkey, szChecks[j])) {
				wprintf(L"%s", szChecks[j]);
				bFound = TRUE;
				break;
			}
		}
		if (bFound) {
			break;
		}
	}
	return bFound;
}
//恶意程序分析工具
DWORD GetProcessIdFromName(LPCTSTR szProcessName)
{
	PROCESSENTRY32 pe32;
	HANDLE hSnapshot = NULL;
	SecureZeroMemory(&pe32, sizeof(PROCESSENTRY32));

	// We want a snapshot of processes
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	// Check for a valid handle, in this case we need to check for
	// INVALID_HANDLE_VALUE instead of NULL
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		wprintf(L"CreateToolhelp32Snapshot");
		return 0;
	}

	// Now we can enumerate the running process, also 
	// we can't forget to set the PROCESSENTRY32.dwSize member
	// otherwise the following functions will fail
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnapshot, &pe32) == FALSE)
	{
		// Cleanup the mess
		wprintf(L"Process32First");
		CloseHandle(hSnapshot);
		return 0;
	}

	// Do our first comparison
	if (StrCmpI(pe32.szExeFile, szProcessName) == 0)
	{
		// Cleanup the mess
		CloseHandle(hSnapshot);
		return pe32.th32ProcessID;
	}

	// Most likely it won't match on the first try so 
	// we loop through the rest of the entries until
	// we find the matching entry or not one at all
	while (Process32Next(hSnapshot, &pe32))
	{
		wprintf(L"%s\n", pe32.szExeFile);
		if (StrCmpI(pe32.szExeFile, szProcessName) == 0)
		{
			// Cleanup the mess
			CloseHandle(hSnapshot);
			return pe32.th32ProcessID;
		}
	}

	// If we made it this far there wasn't a match, so we'll return 0
	// _tprintf(_T("\n-> Process %s is not running on this system ..."), szProcessName);

	CloseHandle(hSnapshot);
	return 0;
}

BOOL analysis() {
	const TCHAR* szProcesses[] = {
	L"ollydbg.exe",			// OllyDebug debugger
	L"ProcessHacker.exe",	// Process Hacker
	L"tcpview.exe",			// Part of Sysinternals Suite
	L"autoruns.exe",			// Part of Sysinternals Suite
	L"autorunsc.exe",		// Part of Sysinternals Suite
	L"filemon.exe",			// Part of Sysinternals Suite
	L"procmon.exe",			// Part of Sysinternals Suite
	L"regmon.exe",			// Part of Sysinternals Suite
	L"procexp.exe",			// Part of Sysinternals Suite
	L"idaq.exe",				// IDA Pro Interactive Disassembler
	L"idaq64.exe",			// IDA Pro Interactive Disassembler
	L"ImmunityDebugger.exe", // ImmunityDebugger
	L"Wireshark.exe",		// Wireshark packet sniffer
	L"dumpcap.exe",			// Network traffic dump tool
	L"HookExplorer.exe",		// Find various types of runtime hooks
	L"ImportREC.exe",		// Import Reconstructor
	L"PETools.exe",			// PE Tool
	L"LordPE.exe",			// LordPE
	L"SysInspector.exe",		// ESET SysInspector
	L"proc_analyzer.exe",	// Part of SysAnalyzer iDefense
	L"sysAnalyzer.exe",		// Part of SysAnalyzer iDefense
	L"sniff_hit.exe",		// Part of SysAnalyzer iDefense
	L"windbg.exe",			// Microsoft WinDbg
	L"joeboxcontrol.exe",	// Part of Joe Sandbox
	L"joeboxserver.exe",		// Part of Joe Sandbox
	L"joeboxserver.exe",		// Part of Joe Sandbox
	L"ResourceHacker.exe",	// Resource Hacker
	L"x32dbg.exe",			// x32dbg
	L"x64dbg.exe",			// x64dbg
	L"Fiddler.exe",			// Fiddler
	L"httpdebugger.exe",		// Http Debugger
	};

	WORD iLength = sizeof(szProcesses) / sizeof(szProcesses[0]);
	for (int i = 0; i < iLength; i++)
	{
		TCHAR msg[256];
		swprintf_s(msg, sizeof(msg) / sizeof(TCHAR), L"Checking process of malware analysis tool: %s ", szProcesses[i]);
		if (GetProcessIdFromName(szProcesses[i]))
		{
			wprintf(L"%s aaa\n", szProcesses[i]);
			return TRUE;
		}
		else {
			wprintf(L"%s bbb\n", szProcesses[i]);
			return FALSE;
		}
	}
}

//debug API
BOOL IsDebuggerPresentAPI()
{
	return IsDebuggerPresent();
}
BOOL IsDebuggerPresentPEB()
{
#if defined (_WIN64)
	PPEB pPeb = (PPEB)__readgsqword(0x60);

#elif defined(_WIN32)
	PPEB pPeb = (PPEB)__readfsdword(0x30);

#endif
	return pPeb->BeingDebugged == 1;
}
BOOL CheckRemoteDebuggerPresentAPI()
{
	BOOL bIsDbgPresent = FALSE;
	CheckRemoteDebuggerPresent(GetCurrentProcess(), &bIsDbgPresent);
	return bIsDbgPresent;
}

BOOL NtGlobalFlag()
{
	PDWORD pNtGlobalFlag = NULL, pNtGlobalFlagWoW64 = NULL;

#if defined (_WIN64)
	pNtGlobalFlag = (PDWORD)(__readgsqword(0x60) + 0xBC);

#elif defined(_WIN32)
	pNtGlobalFlag = (PDWORD)(__readgsqword(0x30) + 0xBC);
#endif

	BOOL normalDetected = pNtGlobalFlag && *pNtGlobalFlag & 0x00000070;
	BOOL wow64Detected = pNtGlobalFlagWoW64 && *pNtGlobalFlagWoW64 & 0x00000070;

	if (normalDetected || wow64Detected)
		return TRUE;
	else
		return FALSE;
}
BOOL HeapFlags()
{
	PUINT32 pHeapFlags = NULL;

#if defined (_WIN64)
	
	PINT64 pProcessHeap = NULL;
	if (IsWindowsVistaOrGreater()) {
		pProcessHeap = (PINT64)(__readgsqword(0x60) + 0x30);
		pHeapFlags = (PUINT32)(*pProcessHeap + 0x70);
}

	else {
		pProcessHeap = (PINT64)(__readgsqword(0x60) + 0x30);
		pHeapFlags = (PUINT32)(*pProcessHeap + 0x14);
	}

#elif defined(_WIN32)
	PUINT32 pProcessHeap, pHeapFlags = NULL;

	if (IsWindowsVistaOrGreater()) {
		pProcessHeap = (PUINT32)(__readfsdword(0x30) + 0x18);
		pHeapFlags = (PUINT32)(*pProcessHeap + 0x40);
	}

	else {
		pProcessHeap = (PUINT32)(__readfsdword(0x30) + 0x18);
		pHeapFlags = (PUINT32)(*pProcessHeap + 0x0C);
	}

#endif

	if (*pHeapFlags > 2)
		return TRUE;
	else
		return FALSE;
}
//判断微信
BOOL we_chat()
{
	HKEY hkResult = NULL;
	const TCHAR* diskEnumKey[] = { 
		L"Software\\Tencent\\WeChat",
		L"Software\\Tencent\\bugReport\\WeChatFiles",
		L"Software\\Tencent\\bugReport\\WechatWindows"
	};
	DWORD diskCount = 0;
	DWORD cbData = sizeof(diskCount);
	BOOL bFound = FALSE;
	WORD dwChecksLength = sizeof(diskEnumKey) / sizeof(diskEnumKey[0]);
	for (unsigned int i = 0; i < dwChecksLength;i++) {
		if (RegOpenKeyEx(HKEY_CURRENT_USER, diskEnumKey[i], NULL, KEY_READ, &hkResult) == ERROR_SUCCESS)
		{
			if (RegQueryValueEx(hkResult, L"Version", NULL, NULL, (LPBYTE)&diskCount, &cbData) == ERROR_SUCCESS)
			{
				RegCloseKey(hkResult);
				printf("1yes\n");
				return bFound;
			}
			RegCloseKey(hkResult);
		}
	}
	LPCSTR fileName = "C:\\Users\\Public\\Desktop\\微信.lnk";
	DWORD attrib = GetFileAttributesA(fileName);

	// 如果函数返回INVALID_FILE_ATTRIBUTES，则文件不存在
	if (attrib == INVALID_FILE_ATTRIBUTES)
	{
		printf("no no\n");
		return bFound = TRUE;
	}
	else
	{
		printf("yes yes\n");
		return bFound;
	}
}

int main() {
	we_chat();
	printf("%d", HeapFlags());
}