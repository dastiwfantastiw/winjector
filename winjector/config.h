#pragma once
#include <Windows.h>
#include <string>

namespace cfg
{
	const DWORD Magic = 0x33F320F4;
	const BYTE  Version = 0x3;

	enum class Type : WORD
	{
		CHAR = 1,
		WIDECHAR = 2,
		ANSI_STRING = 4,
		UNICODE_STRING = 8,
		PROCESS = 16,
		FILE = 32,
		THREAD = 64,
		MUTANT = 128,
		REGKEY = 256,
		SECTION = 512,
		STRINGS = CHAR | WIDECHAR | ANSI_STRING | UNICODE_STRING,
		HANDLE = PROCESS | FILE | THREAD | MUTANT | REGKEY | SECTION
	};

	enum class Flag : WORD
	{
		ENABLED = 1,
		EVENT_ENABLED = 2,
		LOG_BEFORE = 4,
		LOG_AFTER = 8,
		EVENT_LOG_BEFORE = 16,
		EVENT_LOG_AFTER = 32
	};

	enum class AllowLog : BYTE
	{
		ALLOW_NOTHING = 0,
		ALLOW_BEFORE = 1,
		ALLOW_AFTER = 2,
		ALLOW_BOTH = ALLOW_AFTER | ALLOW_BEFORE
	};

	struct Registers
	{
		DWORD EDI;
		DWORD ESI;
		DWORD EBP;
		DWORD ESP;
		DWORD EBX;
		DWORD EDX;
		DWORD ECX;
		DWORD EAX;
	};

#pragma pack(push, 1)
	struct BinSyscall
	{
		union
		{
			DWORD m_Id;
			DWORD m_NameHash;
		} u;
		BOOLEAN   m_IsByNameHash;
		Type      m_Types;
		Flag      m_Flags;
	};

	struct BinApicall
	{
		union
		{
			DWORD m_Ord;
			DWORD m_NameHash;
		} u;
		BOOLEAN   m_IsByNameHash;
		BYTE      m_Conv;
		WORD      m_Argc;
		Type      m_Types;
		Flag      m_Flags;
	};

	struct Syscall
	{
		typedef AllowLog(*Event)(SYSTEMTIME& Time, Syscall* Sys, DWORD* Args, Registers*& Regs, BOOLEAN& IsExecuted);
		std::string	  m_Name;
		DWORD         m_Id;
		LPVOID        m_Address;
		DWORD         m_Signature;
		WORD          m_Argc;
		Type          m_Types;
		Flag          m_Flags;
		Event         m_Event;

		Syscall() :
			m_Name(""),
			m_Id(NULL),
			m_Address(NULL),
			m_Signature(NULL),
			m_Argc(NULL),
			m_Types(Type(NULL)),
			m_Flags(Flag(NULL)),
			m_Event(NULL) {};
	};

	struct Apicall
	{
		std::string m_Name;
		DWORD       m_Ord;
		LPVOID      m_Address;
		DWORD       m_Signature;
		WORD        m_Argc;
		BYTE        m_Conv;
		Type        m_Types;
		Flag        m_Flags;

		Apicall() :
			m_Name(""),
			m_Ord(NULL),
			m_Address(NULL),
			m_Signature(NULL),
			m_Argc(NULL),
			m_Conv(NULL),
			m_Types(Type(NULL)),
			m_Flags(Flag(NULL)) {};
	};

	struct SyscallDllInfo
	{
		DWORD       m_DllHash;
		WORD        m_SyscallCount;
		BOOLEAN     m_IsAllSyscalls;
		Type        m_Types;
		Flag        m_Flags;
		BinSyscall* m_Offset;
	};

	struct ApicallDllInfo
	{
		DWORD       m_DllHash;
		WORD        m_ApicallsCount;
		Type        m_Types;
		Flag        m_Flags;
		BinApicall* m_Offset;
	};

	struct Header
	{
		DWORD           m_Magic;
		WORD            m_Version;
		HANDLE          m_MappingHandle;
		DWORD           m_MappingSize;
		DWORD           m_BinarySize;
		WORD            m_SyscallDllCount;
		WORD            m_ApicallDllCount;
		SyscallDllInfo* m_SyscallDllOffset;
		ApicallDllInfo* m_ApicallDllOffset;
	};

	struct Settings
	{
		BOOLEAN m_IsEnableSyscalls;
		BOOLEAN m_IsEnableApicalls;
		BYTE    m_MaxFrame;
		BYTE    m_MaxPtr;
		DWORD   m_MaxStrLen;
		DWORD   m_MinStrLen;
		WORD    m_PathLength;
		CHAR    m_Path[1];
	};

	struct Config
	{
		Header   m_Header;
		Settings m_Settings;
	};
#pragma pack(pop)
}