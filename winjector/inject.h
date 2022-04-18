#pragma once
#include "config.h"

using namespace cfg;

namespace inject
{
	typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);
	typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);
	typedef BOOL(WINAPI* dllMain)(HMODULE, DWORD, Config*);
	typedef LONG(NTAPI* NtResumeProcess)(HANDLE);
	typedef NTSTATUS(NTAPI* fNtResumeThread)(HANDLE, PULONG);

	struct LoaderData
	{
		pLoadLibraryA fLoadLibraryA;
		pGetProcAddress fGetProcAddress;

		LPVOID imageBase;
		PIMAGE_NT_HEADERS imageNtHeader;
		PIMAGE_BASE_RELOCATION imageBaseReloc;
		PIMAGE_IMPORT_DESCRIPTOR imageImportDesc;

		Config* config;
	};

	inline DWORD WINAPI DllLoader(LoaderData* LData)
	{
		PIMAGE_BASE_RELOCATION pIBR = LData->imageBaseReloc;

		DWORD delta = (DWORD)((LPBYTE)LData->imageBase - LData->imageNtHeader->OptionalHeader.ImageBase);

		while (pIBR->VirtualAddress)
		{
			if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
			{
				int count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				PWORD list = (PWORD)(pIBR + 1);

				for (int i = 0; i < count; i++)
				{
					if (list[i])
					{
						PDWORD ptr = (PDWORD)((LPBYTE)LData->imageBase + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
						*ptr += delta;
					}
				}
			}

			pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
		}

		PIMAGE_IMPORT_DESCRIPTOR pIID = LData->imageImportDesc;

		while (pIID->Characteristics)
		{
			PIMAGE_THUNK_DATA OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)LData->imageBase + pIID->OriginalFirstThunk);
			PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)LData->imageBase + pIID->FirstThunk);

			HMODULE hModule = LData->fLoadLibraryA((LPCSTR)LData->imageBase + pIID->Name);

			if (!hModule)
			{
				return false;
			}

			while (OrigFirstThunk->u1.AddressOfData)
			{
				if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				{
					DWORD Function = (DWORD)LData->fGetProcAddress(hModule,
						reinterpret_cast<char*>(OrigFirstThunk->u1.Ordinal & 0xFFFF));

					if (!Function)
					{
						return false;
					}

					FirstThunk->u1.Function = Function;
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)LData->imageBase + OrigFirstThunk->u1.AddressOfData);
					DWORD Function = (DWORD)LData->fGetProcAddress(hModule, (LPCSTR)pIBN->Name);
					if (!Function)
					{
						return false;
					}

					FirstThunk->u1.Function = Function;
				}
				OrigFirstThunk++;
				FirstThunk++;
			}
			pIID++;
		}

		if (LData->imageNtHeader->OptionalHeader.AddressOfEntryPoint)
		{
			dllMain EntryPoint = (dllMain)((LPBYTE)LData->imageBase + LData->imageNtHeader->OptionalHeader.AddressOfEntryPoint);

			return EntryPoint((HMODULE)LData->imageBase, DLL_PROCESS_ATTACH, LData->config);
		}
		return true;
	}

	inline DWORD WINAPI DllLoaderEnd()
	{
		return NULL;
	}

	bool ManualMappingInjection(HANDLE ProcessHandle, HANDLE DllMap, DWORD DllSize, IMAGE_DOS_HEADER* DllImage, Config* Configuration);
	bool RemoteThreadInjection(HANDLE ProcessHandle, HANDLE DllMap, DWORD DllSize, std::string DllImagePath);
}