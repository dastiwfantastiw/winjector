#include "inject.h"

bool inject::ManualMappingInjection(HANDLE ProcessHandle, HANDLE DllMap, DWORD DllSize, IMAGE_DOS_HEADER* DllImage, Config* Configuration)
{
	if (ProcessHandle == INVALID_HANDLE_VALUE ||
		DllMap == INVALID_HANDLE_VALUE ||
		DllSize == NULL ||
		DllImage == NULL ||
		Configuration == NULL)
	{
		printf("[-] One or more parameters are not initialized for injection\n");
		return false;
	}

	IMAGE_DOS_HEADER* dllDosHeader = DllImage;

	if (dllDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("[-] Dll is invalid\n");
		return false;
	}

	IMAGE_NT_HEADERS* dllNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(dllDosHeader->e_lfanew + reinterpret_cast<BYTE*>(dllDosHeader));
	if (dllNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("[-] Dll is invalid\n");
		return false;
	}

	IMAGE_SECTION_HEADER* dllSecHeader = reinterpret_cast<IMAGE_SECTION_HEADER*>(dllNtHeader + 1);

	LPVOID lpImage = VirtualAllocEx(
		ProcessHandle, NULL, dllNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!lpImage)
	{
		printf("[-] VirtualAllocEx failed (0x%08x)\n", GetLastError());
		return false;
	}

	if (!WriteProcessMemory(
		ProcessHandle, lpImage, dllDosHeader, dllNtHeader->OptionalHeader.SizeOfHeaders, NULL))
	{
		printf("[-] WriteProcessMemory failed (0x%08x)\n", GetLastError());
		VirtualFreeEx(ProcessHandle, lpImage, NULL, MEM_RELEASE);
		return false;
	}

	for (size_t i = 0; i < dllNtHeader->FileHeader.NumberOfSections; i++)
	{
		if (!WriteProcessMemory(
			ProcessHandle,
			reinterpret_cast<LPVOID>(reinterpret_cast<BYTE*>(lpImage) + dllSecHeader[i].VirtualAddress),
			reinterpret_cast<LPVOID>(reinterpret_cast<BYTE*>(dllDosHeader) + dllSecHeader[i].PointerToRawData),
			dllSecHeader[i].SizeOfRawData,
			NULL))
		{
			printf("[-] WriteProcessMemory failed (0x%08x)\n", GetLastError());
			VirtualFreeEx(ProcessHandle, lpImage, NULL, MEM_RELEASE);
			return false;
		}
	}

	Configuration->m_Header.m_MappingHandle = DllMap;
	Configuration->m_Header.m_MappingSize = DllSize;

	LPVOID lpBinary = VirtualAllocEx(
		ProcessHandle, NULL, Configuration->m_Header.m_BinarySize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!lpBinary)
	{
		printf("[-] VirtualAllocEx failed (0x%08x)\n", GetLastError());
		VirtualFreeEx(ProcessHandle, lpImage, NULL, MEM_RELEASE);
		return false;
	}

	if (!WriteProcessMemory(
		ProcessHandle, lpBinary, Configuration, Configuration->m_Header.m_BinarySize, NULL))
	{
		printf("[-] WriteProcessMemory failed (0x%08x)\n", GetLastError());
		VirtualFreeEx(ProcessHandle, lpImage, NULL, MEM_RELEASE);
		VirtualFreeEx(ProcessHandle, lpBinary, NULL, MEM_RELEASE);
		return false;
	}

	LPVOID lpManualData = VirtualAllocEx(
		ProcessHandle, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!lpManualData)
	{
		printf("[-] VirtualAllocEx failed (0x%08x)\n", GetLastError());
		VirtualFreeEx(ProcessHandle, lpImage, NULL, MEM_RELEASE);
		VirtualFreeEx(ProcessHandle, lpBinary, NULL, MEM_RELEASE);
		return false;
	}

	LoaderData data = { 0 };

	data.fLoadLibraryA = LoadLibraryA;
	data.fGetProcAddress = GetProcAddress;

	data.imageBase = lpImage;
	data.imageNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<BYTE*>(lpImage) + dllDosHeader->e_lfanew);
	data.imageBaseReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(lpImage) + dllNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	data.imageImportDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(reinterpret_cast<BYTE*>(lpImage) + dllNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	data.config = reinterpret_cast<Config*>(lpBinary);

	if (!WriteProcessMemory(ProcessHandle, lpManualData, &data, sizeof(data), NULL))
	{
		printf("[-] WriteProcessMemory failed (0x%08x)\n", GetLastError());
		VirtualFreeEx(ProcessHandle, lpImage, NULL, MEM_RELEASE);
		VirtualFreeEx(ProcessHandle, lpBinary, NULL, MEM_RELEASE);
		VirtualFreeEx(ProcessHandle, lpManualData, NULL, MEM_RELEASE);
		return false;
	}

	if (!WriteProcessMemory(ProcessHandle,
		reinterpret_cast<LoaderData*>(lpManualData) + 1,
		DllLoader,
		reinterpret_cast<DWORD>(DllLoaderEnd) - reinterpret_cast<DWORD>(DllLoader),
		NULL))
	{
		printf("[-] WriteProcessMemory failed (0x%08x)\n", GetLastError());
		VirtualFreeEx(ProcessHandle, lpImage, NULL, MEM_RELEASE);
		VirtualFreeEx(ProcessHandle, lpBinary, NULL, MEM_RELEASE);
		VirtualFreeEx(ProcessHandle, lpManualData, NULL, MEM_RELEASE);
		return false;
	}

	HANDLE hThread = CreateRemoteThread(
		ProcessHandle,
		NULL,
		NULL,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(reinterpret_cast<LoaderData*>(lpManualData) + 1),
		lpManualData,
		NULL,
		NULL);

	if (hThread == INVALID_HANDLE_VALUE || hThread == NULL)
	{
		printf("[-] CreateRemoteThread failed (0x%08x)\n", GetLastError());
		VirtualFreeEx(ProcessHandle, lpImage, NULL, MEM_RELEASE);
		VirtualFreeEx(ProcessHandle, lpBinary, NULL, MEM_RELEASE);
		VirtualFreeEx(ProcessHandle, lpManualData, NULL, MEM_RELEASE);
		return false;
	}

	WaitForSingleObject(hThread, INFINITE);
	printf("[+] Injected\n");
	return true;
}

bool inject::RemoteThreadInjection(HANDLE ProcessHandle, HANDLE DllMap, DWORD DllSize, std::string DllImagePath)
{
	if (ProcessHandle == INVALID_HANDLE_VALUE ||
		DllMap == INVALID_HANDLE_VALUE ||
		DllSize == NULL ||
		DllImagePath.empty())
	{
		printf("[-] One or more parameters are not initialized for injection\n");
		return false;
	}

	LPVOID lpPath = VirtualAllocEx(ProcessHandle, NULL, DllImagePath.length() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!lpPath)
	{
		printf("[-] VirtualAllocEx failed (0x%08x)\n", GetLastError());
		return false;
	}

	if (!WriteProcessMemory(ProcessHandle, lpPath, DllImagePath.data(), DllImagePath.length(), NULL))
	{
		printf("[-] WriteProcessMemory failed (0x%08x)\n", GetLastError());
		VirtualFreeEx(ProcessHandle, lpPath, NULL, MEM_RELEASE);
		return false;
	}

	HANDLE hThread = CreateRemoteThread(ProcessHandle, NULL, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryA), lpPath, NULL, NULL);
	if (hThread == INVALID_HANDLE_VALUE || hThread == NULL)
	{
		printf("[-] CreateRemoteThread failed (0x%08x)\n", GetLastError());
		VirtualFreeEx(ProcessHandle, lpPath, NULL, MEM_RELEASE);
		return false;
	}

	WaitForSingleObject(hThread, INFINITE);
	printf("[+] Injected\n");
	return true;
}
