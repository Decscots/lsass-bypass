#pragma once

#if !defined(WIN32_LEAN_AND_MEAN)
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <logger.hpp>
#include <xorstr.hpp>
#include <string>
#include <format>
#include <fstream>
#include <vector>

using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFilename);
using f_GetProcAddress = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);
using NTSTATUS = DWORD;
using NtQuerySystemInformationFn = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
using f_RtlAddFunctionTable = BOOL(WINAPIV*)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

#define SeDebugPriv 20
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)
#define NtCurrentProcess ( (HANDLE)(LONG_PTR) -1 ) 
#define ProcessHandleType 0x7
#define SystemHandleInformation 16 

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;


using _NtQuerySystemInformation = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);

struct MANUAL_MAPPING_DATA {
	f_LoadLibraryA pLoadLibraryA;
	f_GetProcAddress pGetProcAddress;
#ifdef _WIN64
	f_RtlAddFunctionTable pRtlAddFunctionTable;
#endif
	BYTE* pbase;
	HINSTANCE hMod;
	DWORD fdwReasonParam;
	LPVOID reservedParam;
	BOOL SEHSupport;
};

class Process {
private:
	std::string name;
	DWORD processID;
	HANDLE handle;	
	BOOL shouldCloseHandleOnExit;
public:
	explicit Process(std::string const& name, BOOL createNewHandle = TRUE);
	explicit Process();
	~Process();
	DWORD GetProcessID() const;
	bool ChangePrivilege(const char* szPrivilege, BOOL bEnable) const;
	PVOID GetDLLBaseAddress(std::string const& moduleName) const;

	bool LoadLib(std::string const& dllPath);
	bool FreeLib(std::string const& dllName);

	PVOID ManualMap(std::string const& dllPath, LPVOID lpReserved = nullptr) const;
	bool ManualFree(std::string const& dllPath, PVOID address) const;
};