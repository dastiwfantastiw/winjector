#pragma once
#include "config.h"
#include "parser.h"

#include <vector>
#include <map>

using namespace cfg;

namespace jsoner
{
	template<typename T1, typename T2>
	struct DllInfoSet
	{
		T1              m_DllInfo;
		std::vector<T2> m_Binary;
	};

	extern std::map<Flag, std::string> Flags;
	extern std::map<Type, std::string> Types;

	RSJobject GetObjFromJson(RSJresource* Json, std::string Name);
	RSJresource GetItemFromObject(RSJobject& Object, std::string Name);

	template<typename T1>
	extern T1 GetEnumFromObject(RSJobject& Object, std::map<T1, std::string>& Enum);

	template<typename T1>
	extern std::string GetEnumFromValue(T1& Value, std::map<T1, std::string>& Enum);

	bool JSONToConfiguration(const char* JSONPath, Config*& OutConfig);
	bool ReadConfiguration(Config* Config);

	int GetDllNamesFromObject(RSJobject& Object, std::map<std::string, RSJobject*>& OutContainer);
	int GetSycallsInfoFromDlls(std::map<std::string, RSJobject*>& FromContainer, std::vector<DllInfoSet<SyscallDllInfo, BinSyscall>>& OutContainer);
	int GetApicallsInfoFromDlls(std::map<std::string, RSJobject*>& FromContainer, std::vector<DllInfoSet<ApicallDllInfo, BinApicall>>& OutContainer);
}