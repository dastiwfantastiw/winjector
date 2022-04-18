#include "jsoner.h"
#include "adler32.h"

#include <fstream>
#include <algorithm>

namespace jsoner
{
	std::map<Flag, std::string> Flags =
	{
		{Flag::ENABLED, "enabled"},
		{Flag::EVENT_ENABLED, "event_enabled"},
		{Flag::LOG_BEFORE, "log_before"},
		{Flag::LOG_AFTER, "log_after"},
		{Flag::EVENT_LOG_BEFORE, "event_log_before"},
		{Flag::EVENT_LOG_AFTER, "event_log_after"}

	};

	std::map<Type, std::string> Types =
	{
		{Type::CHAR, "char"},
		{Type::WIDECHAR, "widechar"},
		{Type::ANSI_STRING, "ansi_string"},
		{Type::UNICODE_STRING, "unicode_string"},
		{Type::PROCESS, "process"},
		{Type::FILE, "file"},
		{Type::THREAD, "thread"},
		{Type::MUTANT, "mutant"},
		{Type::REGKEY, "regkey"},
		{Type::SECTION, "section"}
	};
}

RSJobject jsoner::GetObjFromJson(RSJresource* Json, std::string Name)
{
	return Json->operator[](Name.c_str()).as_object();
}

RSJresource jsoner::GetItemFromObject(RSJobject& Object, std::string Name)
{
	return Object.operator[](Name.c_str());
}

template<typename T1>
T1 jsoner::GetEnumFromObject(RSJobject& Object, std::map<T1, std::string>& Enum)
{
	T1 flags = T1(NULL);

	for (auto it = Enum.begin(); it != Enum.end(); it++)
	{
		if (Object.operator[](it->second).as<bool>(0))
		{
			flags = static_cast<T1>(static_cast<WORD>(flags) | static_cast<WORD>(it->first));
		}
	}

	return flags;
}
template<typename T1>
std::string jsoner::GetEnumFromValue(T1& Value, std::map<T1, std::string>& Enum)
{
	bool flags = false;
	std::string strValue;

	for (auto it = Enum.begin(); it != Enum.end(); it++)
	{
		if (static_cast<WORD>(it->first) & static_cast<WORD>(Value))
		{
			if (!flags)
			{
				strValue += it->second;
				flags = true;
			}
			else
			{
				strValue += static_cast<std::string>(", ") + it->second;
			}
		}
	}
	return strValue;
}

bool jsoner::JSONToConfiguration(const char* JSONPath, Config*& OutConfig)
{
	if (!JSONPath)
	{
		printf("[-] Invalid JSON path\n");
		return false;
	}

	if (OutConfig)
	{
		delete OutConfig;
	}

	std::ifstream file(JSONPath);

	if (!file.is_open())
	{
		printf("[-] Cannot open the file %s (0x%08x)\n", JSONPath, GetLastError());
		return false;
	}

	RSJresource* json = new RSJresource(file);
	file.close();

	if (!json)
	{
		printf("[-] JSON init failed\n");
		return false;
	}

	RSJobject objSettings = GetObjFromJson(json, "Settings");
	RSJobject objSyscalls = GetObjFromJson(json, "Syscalls");
	RSJobject objApicalls = GetObjFromJson(json, "Apicalls");

	std::map<std::string, RSJobject*> dllsAc;
	std::map<std::string, RSJobject*> dllsSc;

	int objScDllCount = GetDllNamesFromObject(objSyscalls, dllsSc);
	int objAcDllCount = GetDllNamesFromObject(objApicalls, dllsAc);

	std::string logPath = GetItemFromObject(objSettings, "LogPath").as<std::string>();

	std::vector<DllInfoSet<SyscallDllInfo, BinSyscall>> allBinSyscallsFuncData;
	std::vector<DllInfoSet<ApicallDllInfo, BinApicall>> allBinApicallsFuncData;

	int totalScCount = GetSycallsInfoFromDlls(dllsSc, allBinSyscallsFuncData);
	int totalAcCount = GetApicallsInfoFromDlls(dllsAc, allBinApicallsFuncData);

	std::vector<BYTE>* bin = new std::vector<BYTE>;

	size_t size = sizeof(Header) +
		sizeof(Settings) +
		logPath.length() +
		(sizeof(SyscallDllInfo) * (allBinSyscallsFuncData.size() + 1)) +
		(sizeof(ApicallDllInfo) * (allBinApicallsFuncData.size() + 1)) +
		(sizeof(BinSyscall) * totalScCount) +
		(sizeof(BinApicall) * totalAcCount);

	bin->resize(size);

	Config* Configuration = reinterpret_cast<Config*>(bin->data());

	RtlSecureZeroMemory(bin->data(), bin->size());

	Configuration->m_Header.m_Magic = Magic;
	Configuration->m_Header.m_Version = Version;
	Configuration->m_Header.m_ApicallDllCount = allBinApicallsFuncData.size();
	Configuration->m_Header.m_SyscallDllCount = allBinSyscallsFuncData.size();
	Configuration->m_Header.m_BinarySize = size;

	Configuration->m_Settings.m_IsEnableApicalls = GetItemFromObject(objSettings, "IsApicallsEnabled").as<bool>(false);
	Configuration->m_Settings.m_IsEnableSyscalls = GetItemFromObject(objSettings, "IsSyscallsEnabled").as<bool>(false);
	Configuration->m_Settings.m_MaxFrame = GetItemFromObject(objSettings, "MaxFrame").as<int>(0x10);
	Configuration->m_Settings.m_MaxPtr = GetItemFromObject(objSettings, "MaxPointer").as<int>(0);
	Configuration->m_Settings.m_MinStrLen = GetItemFromObject(objSettings, "MinStrLength").as<int>(1);
	Configuration->m_Settings.m_MaxStrLen = GetItemFromObject(objSettings, "MaxStrLength").as<int>(255);

	Configuration->m_Settings.m_PathLength = logPath.length() + 1;
	memcpy_s(&Configuration->m_Settings.m_Path, logPath.length(), logPath.c_str(), logPath.length());

	SyscallDllInfo* secSyscallDllInfo = reinterpret_cast<SyscallDllInfo*>(&Configuration->m_Settings.m_Path + Configuration->m_Settings.m_PathLength);
	ApicallDllInfo* secApicallDllInfo = reinterpret_cast<ApicallDllInfo*>(&secSyscallDllInfo[allBinSyscallsFuncData.size() + 1]);

	Configuration->m_Header.m_SyscallDllOffset = reinterpret_cast<SyscallDllInfo*>(reinterpret_cast<DWORD>(secSyscallDllInfo) - reinterpret_cast<DWORD>(Configuration));
	Configuration->m_Header.m_ApicallDllOffset = reinterpret_cast<ApicallDllInfo*>(reinterpret_cast<DWORD>(secApicallDllInfo) - reinterpret_cast<DWORD>(Configuration));

	BinSyscall* secBinSys = reinterpret_cast<BinSyscall*>(secApicallDllInfo + 1);

	for (auto it = allBinSyscallsFuncData.begin(); it != allBinSyscallsFuncData.end(); it++)
	{
		if (!it->m_Binary.empty())
		{
			it->m_DllInfo.m_Offset = reinterpret_cast<BinSyscall*>(reinterpret_cast<DWORD>(secBinSys) - reinterpret_cast<DWORD>(Configuration));
		}
		else
		{
			it->m_DllInfo.m_Offset = NULL;
		}

		memcpy_s(secSyscallDllInfo, sizeof(SyscallDllInfo), &it->m_DllInfo, sizeof(SyscallDllInfo));
		memcpy_s(secBinSys, sizeof(BinSyscall) * it->m_Binary.size(), it->m_Binary.data(), sizeof(BinSyscall) * it->m_Binary.size());

		secBinSys += it->m_Binary.size();

		secSyscallDllInfo++;
	}

	BinApicall* secBinApi = reinterpret_cast<BinApicall*>(secBinSys);

	for (auto it = allBinApicallsFuncData.begin(); it != allBinApicallsFuncData.end(); it++)
	{
		if (!it->m_Binary.empty())
		{
			it->m_DllInfo.m_Offset = reinterpret_cast<BinApicall*>(reinterpret_cast<DWORD>(secBinApi) - reinterpret_cast<DWORD>(Configuration));
		}
		else
		{
			it->m_DllInfo.m_Offset = NULL;
		}

		memcpy_s(secApicallDllInfo, sizeof(ApicallDllInfo), &it->m_DllInfo, sizeof(ApicallDllInfo));
		memcpy_s(secBinApi, sizeof(BinApicall) * it->m_Binary.size(), it->m_Binary.data(), sizeof(BinApicall) * it->m_Binary.size());

		secBinApi += it->m_Binary.size();

		secApicallDllInfo++;
	}

	OutConfig = Configuration;
	printf("[+] JSON file %s converted successfully\n", JSONPath);
	return true;
}

bool jsoner::ReadConfiguration(Config* Config)
{
	if (!Config)
	{
		printf("[-] Please initialize config before read it\n");
		return false;
	}

	if (Config->m_Header.m_Magic != Magic || 
		Config->m_Header.m_Version != Version)
	{
		printf("[-] The configuration has invalid magic (0x%08x) or version (0x%04x)\n", 
			Config->m_Header.m_Magic, 
			Config->m_Header.m_Version);
		return false;
	}

	Header* head = &Config->m_Header;
	Settings* sets = &Config->m_Settings;

	printf("[+] Configuration: \n");
	printf(
		"\tMagic : 0x%08x\n"
		"\tVersion : 0x%04x\n"
		"\tSize : 0x%x (%d bytes)\n"
		"\tMap : 0x%x\n"
		"\tMapSize : 0x%08x (%d bytes)\n"
		"\tLogPath : \"%s\" (%d bytes)\n"
		"\tIsApicallsEnabled : %s\n"
		"\tIsSyscallsEnabled : %s\n"
		"\tMaxFrame : 0x%x (%d)\n"
		"\tMaxPointer : 0x%x (%d)\n"
		"\tMaxStrLength : 0x%x (%d)\n"
		"\tMinStrLength : 0x%x (%d)\n",
		Config->m_Header.m_Magic,
		Config->m_Header.m_Version,
		Config->m_Header.m_BinarySize, Config->m_Header.m_BinarySize,
		Config->m_Header.m_MappingHandle,
		Config->m_Header.m_MappingSize, Config->m_Header.m_MappingSize,
		reinterpret_cast<char*>(Config->m_Settings.m_Path), Config->m_Settings.m_PathLength,
		Config->m_Settings.m_IsEnableApicalls ? "true" : "false",
		Config->m_Settings.m_IsEnableSyscalls ? "true" : "false",
		Config->m_Settings.m_MaxFrame, Config->m_Settings.m_MaxFrame,
		Config->m_Settings.m_MaxPtr, Config->m_Settings.m_MaxPtr,
		Config->m_Settings.m_MaxStrLen, Config->m_Settings.m_MaxStrLen,
		Config->m_Settings.m_MinStrLen, Config->m_Settings.m_MinStrLen);

	SyscallDllInfo* secSyscallDllInfo = reinterpret_cast<SyscallDllInfo*>(reinterpret_cast<DWORD>(head->m_SyscallDllOffset) + reinterpret_cast<DWORD>(Config));
	ApicallDllInfo* secApicallDllInfo = reinterpret_cast<ApicallDllInfo*>(reinterpret_cast<DWORD>(head->m_ApicallDllOffset) + reinterpret_cast<DWORD>(Config));

	if (head->m_SyscallDllCount && secSyscallDllInfo)
	{
		printf("\t<Syscalls> : DLLs = %d, Offset = 0x%x (%d)\n",
			Config->m_Header.m_SyscallDllCount,
			Config->m_Header.m_SyscallDllOffset, Config->m_Header.m_SyscallDllOffset);

		for (size_t i = 0; i < head->m_SyscallDllCount; i++)
		{
			printf("\t   <%d> DLLHash = 0x%08x, Count = %d, All = %s, Types = 0x%08x [%s], Flags = 0x%08x [%s]\n",
				i + 1,
				secSyscallDllInfo[i].m_DllHash,
				secSyscallDllInfo[i].m_SyscallCount,
				secSyscallDllInfo[i].m_IsAllSyscalls ? "true" : "false",
				secSyscallDllInfo[i].m_Types,
				GetEnumFromValue(secSyscallDllInfo[i].m_Types, Types).c_str(),
				secSyscallDllInfo[i].m_Flags,
				GetEnumFromValue(secSyscallDllInfo[i].m_Flags, Flags).c_str());

			if (secSyscallDllInfo[i].m_Offset)
			{
				BinSyscall* syscall = reinterpret_cast<BinSyscall*>(reinterpret_cast<DWORD>(secSyscallDllInfo[i].m_Offset) + reinterpret_cast<DWORD>(Config));

				for (size_t j = 0; j < secSyscallDllInfo[i].m_SyscallCount; j++)
				{
					printf("\t     #%d %s = 0x%08x, Types = 0x%08x [%s], Flags = 0x%08x [%s]\n",
						j + 1,
						syscall[j].m_IsByNameHash ? "NameHash" : "Id",
						syscall[j].m_IsByNameHash ? syscall[j].u.m_NameHash : syscall[j].u.m_Id,
						syscall[j].m_Types,
						GetEnumFromValue<Type>(syscall[i].m_Types, Types).c_str(),
						syscall[i].m_Flags,
						GetEnumFromValue<Flag>(syscall[i].m_Flags, Flags).c_str());
				}
			}
		}
	}

	if (head->m_ApicallDllCount && secApicallDllInfo)
	{
		printf("\t<Apicalls> : DLLs = %d, Offset = 0x%x (%d)\n",
			Config->m_Header.m_ApicallDllCount,
			Config->m_Header.m_ApicallDllOffset, Config->m_Header.m_ApicallDllOffset);

		for (size_t i = 0; i < head->m_ApicallDllCount; i++)
		{
			printf("\t   <%d> DLLHash = 0x%08x, Count = %d, Types = 0x%08x [%s], Flags = 0x%08x [%s]\n",
				i + 1,
				secApicallDllInfo[i].m_DllHash,
				secApicallDllInfo[i].m_ApicallsCount,
				secApicallDllInfo[i].m_Types,
				GetEnumFromValue<Type>(secApicallDllInfo[i].m_Types, Types).c_str(),
				secApicallDllInfo[i].m_Flags,
				GetEnumFromValue<Flag>(secApicallDllInfo[i].m_Flags, Flags).c_str());

			if (secApicallDllInfo[i].m_Offset)
			{
				BinApicall* apicall = reinterpret_cast<BinApicall*>(reinterpret_cast<DWORD>(secApicallDllInfo[i].m_Offset) + reinterpret_cast<DWORD>(Config));

				for (size_t j = 0; j < secApicallDllInfo[i].m_ApicallsCount; j++)
				{
					printf("\t     #%d %s = 0x%08x, Types = 0x%08x [%s], Flags = 0x%08x [%s]\n",
						j + 1,
						apicall[j].m_IsByNameHash ? "NameHash" : "Ord",
						apicall[j].m_IsByNameHash ? apicall[j].u.m_NameHash : apicall[j].u.m_Ord,
						apicall[j].m_Types,
						GetEnumFromValue<Type>(apicall[i].m_Types, Types).c_str(),
						apicall[i].m_Flags,
						GetEnumFromValue<Flag>(apicall[i].m_Flags, Flags).c_str());
				}
			}
		}
	}
	return true;
}

int jsoner::GetDllNamesFromObject(RSJobject& Object, std::map<std::string, RSJobject*>& OutContainer)
{
	OutContainer.clear();
	for (auto it = Object.begin(); it != Object.end(); it++)
	{
		auto object = &it->second.as_object();
		if (!object->size())
		{
			continue;
		}

		std::string dest = it->first;

		size_t fileName = dest.find_last_of('\\');
		if (fileName != 0xffffffff)
		{
			dest = dest.substr(fileName + 1);
		}

		size_t fileName2 = dest.find_last_of('/');
		if (fileName2 != 0xffffffff)
		{
			dest = dest.substr(fileName2 + 1);
		}

		size_t extension = dest.find_last_of('.');
		if (extension != 0xffffffff)
		{
			dest = dest.substr(NULL, extension);
		}

		std::transform(dest.begin(), dest.end(), dest.begin(), [](unsigned char c) { return std::tolower(c); });

		OutContainer.insert(std::pair<std::string, RSJobject*>(dest, object));
	}
	return OutContainer.size();
}

int jsoner::GetSycallsInfoFromDlls(std::map<std::string, RSJobject*>& FromContainer, std::vector<DllInfoSet<SyscallDllInfo, BinSyscall>>& OutContainer)
{
	int totalScCount = NULL;
	for (auto it = FromContainer.begin(); it != FromContainer.end(); it++)
	{
		std::vector<BinSyscall> tmpBins;
		SyscallDllInfo tmpDllInfo = { 0 };

		auto item = GetItemFromObject(*it->second, "All");
		if (item.exists())
		{
			tmpDllInfo.m_IsAllSyscalls = true;
			tmpDllInfo.m_Types = GetEnumFromObject<Type>(item.as_object(), Types);
			tmpDllInfo.m_Flags = GetEnumFromObject<Flag>(item.as_object(), Flags);
		}
		else
		{
			tmpDllInfo.m_IsAllSyscalls = false;
		}

		item = GetItemFromObject(*it->second, "Id");
		if (item.exists())
		{
			for (auto ids = item.as_object().begin(); ids != item.as_object().end(); ids++)
			{
				auto params = ids->second.as_object();

				DWORD id = 0;
				sscanf_s(ids->first.c_str(), "%x", &id);

				if (id != 0)
				{
					tmpBins.push_back(
						{
							id,
							false,
							GetEnumFromObject<Type>(params, Types),
							GetEnumFromObject<Flag>(params, Flags)
						});
				}
			}
		}

		item = GetItemFromObject(*it->second, "Name");
		if (item.exists())
		{
			for (auto names = item.as_object().begin(); names != item.as_object().end(); names++)
			{
				auto params = names->second.as_object();

				tmpBins.push_back(
					{
						adler32(names->first.c_str(), names->first.length()),
						true,
						GetEnumFromObject<Type>(params, Types),
						GetEnumFromObject<Flag>(params, Flags)
					});
			}
		}

		if (tmpBins.empty() && !tmpDllInfo.m_IsAllSyscalls)
		{
			continue;
		}

		tmpDllInfo.m_DllHash = adler32(it->first.c_str(), it->first.length());
		tmpDllInfo.m_SyscallCount = tmpBins.size();

		totalScCount += tmpDllInfo.m_SyscallCount;

		OutContainer.push_back({ tmpDllInfo, tmpBins });
	}
	return totalScCount;
}

int jsoner::GetApicallsInfoFromDlls(std::map<std::string, RSJobject*>& FromContainer, std::vector<DllInfoSet<ApicallDllInfo, BinApicall>>& OutContainer)
{
	int totalAcCount = 0;
	for (auto it = FromContainer.begin(); it != FromContainer.end(); it++)
	{
		std::vector<BinApicall> tmpBins;
		ApicallDllInfo tmpDllInfo = { 0 };

		auto item = GetItemFromObject(*it->second, "Ordinal");
		if (item.exists())
		{
			for (auto ords = item.as_object().begin(); ords != item.as_object().end(); ords++)
			{
				auto params = ords->second.as_object();

				WORD argc = GetItemFromObject(params, "argc").as<int>(-1);
				if (argc == 0xffff)
					continue;

				DWORD ordinal = atoi(ords->first.c_str());
				if (ordinal == 0xffff)
					continue;

				BYTE conv = GetItemFromObject(params, "conv").as<int>(0);

				tmpBins.push_back(
					{
						ordinal,
						false,
						conv,
						argc,
						GetEnumFromObject<Type>(params, Types),
						GetEnumFromObject<Flag>(params, Flags)
					});
			}
		}

		item = GetItemFromObject(*it->second, "Name");
		if (item.exists())
		{
			for (auto names = item.as_object().begin(); names != item.as_object().end(); names++)
			{
				auto params = names->second.as_object();

				WORD argc = GetItemFromObject(params, "argc").as<int>(-1);
				if (argc == 0xffff)
					continue;

				BYTE conv = GetItemFromObject(params, "conv").as<int>(0);

				tmpBins.push_back(
					{
						adler32(names->first.c_str(), names->first.length()),
						true,
						conv,
						argc,
						GetEnumFromObject<Type>(params, Types),
						GetEnumFromObject<Flag>(params, Flags)
					});
			}
		}

		if (tmpBins.empty())
		{
			continue;
		}

		tmpDllInfo.m_DllHash = adler32(it->first.c_str(), it->first.length());
		tmpDllInfo.m_ApicallsCount = tmpBins.size();

		totalAcCount += tmpDllInfo.m_ApicallsCount;

		OutContainer.push_back({ tmpDllInfo, tmpBins });
	}
	return totalAcCount;
}
