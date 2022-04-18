#pragma once
#include "inject.h"

namespace winjector
{
	class Winjector
	{
	private:
		struct
		{
			STARTUPINFOA m_StartInfo;
			PROCESS_INFORMATION m_ProcessInfo;

			std::string m_ImagePath;
			std::string m_CommandLine;
		} Process;

		struct
		{
			bool m_WaitInjectionFlag;
			Config* m_Configuration;
			HANDLE m_DllMap;
			DWORD m_DllSize;
			IMAGE_DOS_HEADER* m_DllImage;
			std::string m_DllImagePath;
		} Inject;

	public:
		Winjector();

		void ShowUsage();
		bool JSONToConfiguration(char* JSONPath);
		bool SaveConfiguration(char* FilePath);
		bool ReadConfiguration(char Op);
		bool LoadConfiguration(char* FilePath);
		void SetProcessImagePath(char* ImagePath);
		void SetProcessCommandLine(char* CommandLine);
		void SetWaitInjectionFlag(char Op);
		bool LoadDll(char* DllPath);
#undef CreateProcess
		bool CreateProcess(DWORD Flags);
		bool Execute(char Op);
	};
}