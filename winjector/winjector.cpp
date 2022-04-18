#include "winjector.h"
#include "jsoner.h"

winjector::Winjector::Winjector()
{
	Process.m_CommandLine.clear();
	Process.m_ImagePath.clear();
	Process.m_StartInfo = { 0 };
	Process.m_ProcessInfo = { 0 };

	Inject.m_WaitInjectionFlag = false;
	Inject.m_Configuration = NULL;
	Inject.m_DllMap = INVALID_HANDLE_VALUE;
	Inject.m_DllSize = NULL;
	Inject.m_DllImage = NULL;
	Inject.m_DllImagePath.clear();
}

void winjector::Winjector::ShowUsage()
{
	printf(
		"[+] Options:\n"
		"        -c <path> : Convert the specified JSON file to binary data\n"
		"        -s <path> : Save initialized binary data\n"
		"        -r <path> : Read initialized binary data\n"
		"        -b <path> : Initialize binary from disk\n"
		"        -i <path> : Initialize image process to create new process\n"
		"        -a <str>  : Specifi command line for the process\n"
		"        -d <path> : Initialize watcher\n"
		"        -e : Execute\n",
		"        -h : Print this help\n");

	printf("\n[+] Flags:\n");
	for (auto it = jsoner::Flags.begin(); it != jsoner::Flags.end(); it++)
	{
		printf("         '%s': 0x%08x\n", it->second.c_str(), it->first);
	}

	printf("\n[+] Types:\n");
	for (auto it = jsoner::Types.begin(); it != jsoner::Types.end(); it++)
	{
		printf("         '%s': 0x%08x\n", it->second.c_str(), it->first);
	}
}

bool winjector::Winjector::JSONToConfiguration(char* JSONPath)
{
	return jsoner::JSONToConfiguration(JSONPath, Inject.m_Configuration);
}

bool winjector::Winjector::SaveConfiguration(char* FilePath)
{
	if (!Inject.m_Configuration)
	{
		return false;
	}

	HANDLE fileHandle = CreateFileA(FilePath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fileHandle == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	bool result = WriteFile(fileHandle, Inject.m_Configuration, Inject.m_Configuration->m_Header.m_BinarySize, NULL, NULL);
	CloseHandle(fileHandle);
	return result;
}

bool winjector::Winjector::ReadConfiguration(char Op)
{
	return jsoner::ReadConfiguration(Inject.m_Configuration);
}

bool winjector::Winjector::LoadConfiguration(char* FilePath)
{
	HANDLE fileHandle = CreateFileA(FilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (fileHandle == INVALID_HANDLE_VALUE)
	{
		printf("[-] CreateFileA failed (0x%08x)\n", GetLastError());
		return false;
	}

	DWORD fileSize = GetFileSize(fileHandle, NULL);

	if (fileSize)
	{
		byte* config = new byte[fileSize];
		if (!config)
		{
			CloseHandle(fileHandle);
			return false;
		}

		if (!ReadFile(fileHandle, config, fileSize, NULL, NULL))
		{
			printf("[-] ReadFile failed (0x%08x)\n", GetLastError());
			delete[] config;
			CloseHandle(fileHandle);
			return false;
		}

		if (reinterpret_cast<Config*>(config)->m_Header.m_Magic != Magic ||
			reinterpret_cast<Config*>(config)->m_Header.m_Version != Version)
		{
			printf("[-] The configuration has invalid magic (0x%08x) or version (0x%04x)\n",
				reinterpret_cast<Config*>(config)->m_Header.m_Magic,
				reinterpret_cast<Config*>(config)->m_Header.m_Version);

			delete[] config;
			CloseHandle(fileHandle);
			return false;
		}

		if (Inject.m_Configuration)
		{
			delete Inject.m_Configuration;
		}

		Inject.m_Configuration = reinterpret_cast<Config*>(config);
		CloseHandle(fileHandle);
		printf("[+] Configuration loaded\n");
		return true;
	}

	CloseHandle(fileHandle);
	return false;
}

void winjector::Winjector::SetProcessCommandLine(char* CommandLine)
{
	Process.m_CommandLine = CommandLine;
}

void winjector::Winjector::SetWaitInjectionFlag(char Op)
{
	Inject.m_WaitInjectionFlag = true;
}

bool winjector::Winjector::LoadDll(char* DllPath)
{
	HANDLE fileHandle = CreateFileA(DllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (fileHandle == INVALID_HANDLE_VALUE)
	{
		printf("[-] CreateFileA failed (0x%08x)\n", GetLastError());
		return false;
	}

	DWORD fileSize = GetFileSize(fileHandle, NULL);

	if (fileSize)
	{
		Inject.m_DllMap = CreateFileMappingA(fileHandle, NULL, PAGE_READONLY, NULL, NULL, NULL);
		if (Inject.m_DllMap == INVALID_HANDLE_VALUE || !Inject.m_DllMap)
		{
			printf("[-] CreateFileMappingA failed (0x%08x)\n", GetLastError());
			CloseHandle(fileHandle);
			return false;
		}

		CloseHandle(fileHandle);

		Inject.m_DllImage = reinterpret_cast<IMAGE_DOS_HEADER*>(MapViewOfFile(Inject.m_DllMap, FILE_MAP_READ, NULL, NULL, fileSize));
		if (!Inject.m_DllImage)
		{
			printf("[-] MapViewOfFile failed (0x%08x)\n", GetLastError());
			CloseHandle(Inject.m_DllMap);
			Inject.m_DllMap = INVALID_HANDLE_VALUE;
			Inject.m_DllImage = NULL;
			return false;
		}

		Inject.m_DllImagePath = DllPath;
		Inject.m_DllSize = fileSize;

		printf("[+] Dll loaded : %s\n", DllPath);
		return true;
	}

	return false;
}

bool winjector::Winjector::CreateProcess(DWORD Flags)
{
	Process.m_StartInfo.cb = sizeof(Process.m_StartInfo);

	HANDLE hToken = INVALID_HANDLE_VALUE;
	LUID luid = { 0 };
	TOKEN_PRIVILEGES tokenPriv = { 0 };

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
		{
			tokenPriv.PrivilegeCount = 1;
			tokenPriv.Privileges[0].Luid = luid;
			tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(tokenPriv), NULL, NULL);
		}
	}

	return CreateProcessA(
		Process.m_ImagePath.empty() ? NULL : Process.m_ImagePath.c_str(),
		Process.m_CommandLine.empty() ? NULL : const_cast<char*>(Process.m_CommandLine.c_str()),
		NULL,
		NULL,
		false,
		Flags,
		NULL,
		NULL,
		&Process.m_StartInfo,
		&Process.m_ProcessInfo);
}

bool winjector::Winjector::Execute(char Op)
{
	if (Inject.m_DllImage == NULL || Inject.m_DllImagePath.empty() ||
		Inject.m_DllMap  == INVALID_HANDLE_VALUE || Inject.m_DllSize == NULL)
	{
		printf("[-] Dll is not initialized\n");
		return false;
	}

	if (!Inject.m_Configuration)
	{
		printf("[-] Configuration is not initialized\n");
		return false;
	}

	if (!CreateProcess(CREATE_SUSPENDED | CREATE_DEFAULT_ERROR_MODE | CREATE_NEW_CONSOLE))
	{
		printf("[-] CreateProcessA failed (0x%08x)\n", GetLastError());
		CloseHandle(Inject.m_DllMap);
		UnmapViewOfFile(Inject.m_DllImage);
		return false;
	}
	
	printf("[+] Pid : 0x%04x (%d)\n", Process.m_ProcessInfo.dwProcessId, Process.m_ProcessInfo.dwProcessId);
	printf("[+] Tid : 0x%04x (%d)\n", Process.m_ProcessInfo.dwThreadId, Process.m_ProcessInfo.dwThreadId);
	printf("[+] ImagePath : \"%s\"\n", Process.m_ImagePath.c_str());
	printf("[+] CmdLine : \"%s\"\n", Process.m_CommandLine.c_str());

	USHORT ProcessMachine = 0;
	USHORT NativeMachine = 0;

	if (IsWow64Process2(Process.m_ProcessInfo.hProcess, &ProcessMachine, &NativeMachine) &&
		IMAGE_FILE_MACHINE_UNKNOWN == ProcessMachine)
	{
		printf("[-] The created process is 64-bit application. Terminating...\n");
		TerminateProcess(Process.m_ProcessInfo.hProcess, -1);
		CloseHandle(Inject.m_DllMap);
		UnmapViewOfFile(Inject.m_DllImage);
		return false;
	}

	HANDLE dupMap = INVALID_HANDLE_VALUE;

	if (!DuplicateHandle(GetCurrentProcess(), Inject.m_DllMap, Process.m_ProcessInfo.hProcess, &dupMap, NULL, false, DUPLICATE_SAME_ACCESS))
	{
		printf("[-] DuplicateHandle failed (0x%08x)\n", GetLastError());
		TerminateProcess(Process.m_ProcessInfo.hProcess, -1);
		CloseHandle(Inject.m_DllMap);
		UnmapViewOfFile(Inject.m_DllImage);
		return false;
	}

	printf("[+] DupMap : 0x%08x\n", dupMap);

	if (Inject.m_WaitInjectionFlag)
	{
		printf("[~] Press Enter to continue injection\n");
		getchar();
	}

	bool injectResult = false;

	switch (Op)
	{
		case 'e':
		{
			injectResult = inject::ManualMappingInjection(Process.m_ProcessInfo.hProcess, dupMap, Inject.m_DllSize, Inject.m_DllImage, Inject.m_Configuration);
			break;
		}

		case 'E':
		{
			injectResult = inject::RemoteThreadInjection(Process.m_ProcessInfo.hProcess, dupMap, Inject.m_DllSize, Inject.m_DllImagePath);
			break;
		}
	}

	CloseHandle(Inject.m_DllMap);
	UnmapViewOfFile(Inject.m_DllImage);

	if (!injectResult || !ResumeThread(Process.m_ProcessInfo.hThread))
	{
		TerminateProcess(Process.m_ProcessInfo.hProcess, -1);
		return false;
	}

	printf("[+] Executed\n");
	return injectResult;
}

void winjector::Winjector::SetProcessImagePath(char* ImagePath)
{
	Process.m_ImagePath = ImagePath;
}
