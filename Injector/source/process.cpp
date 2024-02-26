// MIT-licensed code from Simple-Manual-Map-Injector by TheCruZ
// Source: https://github.com/TheCruZ/Simple-Manual-Map-Injector/
// Lines 237 to 555

#include <process.hpp>

Process::Process(std::string const& name, BOOL createNewHandle) : name(name), processID(this->GetProcessID()), handle(nullptr), shouldCloseHandleOnExit(createNewHandle) {
	if (createNewHandle) {
		this->handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, this->processID);
		return;
	}	

	auto NtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformationFn>(GetProcAddress(GetModuleHandleA(xorstr_("ntdll.dll")), xorstr_("NtQuerySystemInformation")));
	DWORD status;
	ULONG handleInfoSize = 0x10000;

	std::vector<char> handleInfo(handleInfoSize);

	while ((status = NtQuerySystemInformation(SystemHandleInformation, handleInfo.data(), handleInfoSize, nullptr)) == STATUS_INFO_LENGTH_MISMATCH)
		handleInfo.resize(handleInfoSize *= 2);

	if (!NT_SUCCESS(status)) {
		Log(xorstr_("NtQuerySystemInformation failed!"));
		throw std::runtime_error(std::format(""));
	}

	for (auto i = 0; i < reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(handleInfo.data())->HandleCount; i++) {
		auto handle = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(handleInfo.data())->Handles[i];
		if (handle.ObjectTypeNumber != ProcessHandleType)
			continue;

		const auto process = reinterpret_cast<HANDLE>(handle.Handle);
		if (handle.ProcessId == GetCurrentProcessId() && GetProcessId(process) == this->processID) {
			this->handle = process;
			break;
		}
	}
}

Process::Process() : name(xorstr_("")), processID(GetCurrentProcessId()), handle(GetCurrentProcess()), shouldCloseHandleOnExit(FALSE) {}

DWORD Process::GetProcessID() const {
	/* Create the snapshot */
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	/* Check if snapshot was created correctly */
	if (hSnap == INVALID_HANDLE_VALUE || hSnap == 0) {
		Log(xorstr_("Couldn't create a snapshot"));
		throw std::runtime_error(std::format(""));
	}

	/* Initialize the process entry */
	PROCESSENTRY32 entry{};
	entry.dwSize = sizeof(PROCESSENTRY32);
	DWORD pid = 0;
	if (Process32First(hSnap, &entry)) {
		/* Loop through the processes */
		do {
			/* If the current process name is equal to the target name, we got it */
			if (!lstrcmpi(entry.szExeFile, name.c_str())) {
				pid = entry.th32ProcessID;
				break;
			}
		} while (Process32Next(hSnap, &entry));
	}
	/* If we didn't find anything, this->processID will be NULL */
	if (pid == NULL) {
		Log(xorstr_("Couldn't find target process: ") << name);
		throw std::runtime_error(std::format(""));
	}

	/* Close the snapshot since we're not going to use it anymore */
	CloseHandle(hSnap);
	return pid;
}

bool Process::ChangePrivilege(const char* privilege, BOOL bEnable) const {
	/* Get the token */
	HANDLE hToken;
	if (!OpenProcessToken(this->handle, TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		Log(xorstr_("FAILED TO GET TOKEN!!"));
		return false;
	}

	/* Get the LUID */
	LUID luid;
	if (!LookupPrivilegeValue(nullptr, privilege, &luid)) {
		Log(xorstr_("FAILED TO GET LUID!!"));
		return false;
	}

	/* Set the privilege */
	TOKEN_PRIVILEGES tp{};
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
		Log(xorstr_("FAILED TO SET PRIVILEGE!!"));
		return false;
	}

	CloseHandle(hToken);
	return true;
}

Process::~Process() {
	/* We DO NOT want to close hijacked handles */
	if (this->shouldCloseHandleOnExit)
		CloseHandle(this->handle);
}

PVOID Process::GetDLLBaseAddress(std::string const& moduleName) const {
	/* Create the snapshot */
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, this->processID);

	/* Check if snapshot was created correctly */
	if (hSnap == INVALID_HANDLE_VALUE || hSnap == 0) {
		Log(xorstr_("Couldn't create a snapshot"));
		throw std::runtime_error(std::format(""));
	}

	/* Initialize the process entry */
	MODULEENTRY32 entry{};
	entry.dwSize = sizeof(MODULEENTRY32);
	
	PVOID hModule = NULL;

	if (Module32First(hSnap, &entry)) {
		/* Loop through the modules */
		do {
			/* If the current module name is equal to the target name, we got it */
			if (!lstrcmpi(entry.szModule, moduleName.c_str())) {
				hModule = entry.hModule;
				break;
			}
		} while (Module32Next(hSnap, &entry));
	}

	/* Close the snapshot since we're not going to use it anymore */
	CloseHandle(hSnap);
	return hModule;
}

bool Process::LoadLib(std::string const& dllPath) {
	/* Allocate memory to write the dll's path in the target process */
	const LPVOID lpPathAddress = VirtualAllocEx(this->handle, nullptr, dllPath.length() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpPathAddress == nullptr) {
		Log(xorstr_("FAILED TO ALLOCATE MEMORY!!"));
		return false;
	}

	/* Write the dllPath in the allocated memory */
	const DWORD dwWriteResult = WriteProcessMemory(this->handle, lpPathAddress, dllPath.c_str(), dllPath.length() + 1, nullptr);
	if (dwWriteResult == 0) {
		Log(xorstr_("FAILED TO WRITE MEMORY!!"));
		return false;
	}

	/* Get the kernel32.dll addresss to get LoadLibraryA address */
	const HMODULE hModule = GetModuleHandleA(xorstr_("kernel32.dll"));
	if (hModule == INVALID_HANDLE_VALUE || hModule == nullptr) {
		Log(xorstr_("FAILED TO GET KERNEL32.DLL!!"));
		return false;
	}

	/* Get the LoadLibraryA address */
	const FARPROC lpFunctionAddress = GetProcAddress(hModule, xorstr_("LoadLibraryA"));
	if (lpFunctionAddress == nullptr) {
		Log(xorstr_("FAILED TO GET LOADLIBRARYA!!"));
		return false;
	}

	/* Create the LoadLibraryA thread on the process */
	const HANDLE hThreadCreationResult = CreateRemoteThread(this->handle, nullptr, 0, (LPTHREAD_START_ROUTINE)lpFunctionAddress, lpPathAddress, 0, nullptr);
	if (hThreadCreationResult == INVALID_HANDLE_VALUE || hThreadCreationResult == NULL) {
		Log(xorstr_("FAILED TO CREATEREMOTETHREAD!!"));
		return false;
	}

	/* Wait for thread to finish */
	WaitForSingleObject(hThreadCreationResult, INFINITE);
	CloseHandle(hThreadCreationResult);

	return true;
}

bool Process::FreeLib(std::string const& dllName) {
	/* Get a handle to the dll */
	const HINSTANCE hLibrary = reinterpret_cast<HINSTANCE>(this->GetDLLBaseAddress(dllName));
	if (hLibrary == INVALID_HANDLE_VALUE) {
		Log(xorstr_("FAILED TO GET DLL!!"));
		return false;
	}

	/* Allocate memory to write the dll's handle in the target process */
	const LPVOID lpHandleAddress = VirtualAllocEx(this->handle, nullptr, sizeof(HINSTANCE), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpHandleAddress == nullptr) {
		Log(xorstr_("FAILED TO ALLOCATE MEMORY!!"));
		return false;
	}

	/* Write the dllPath in the allocated memory */
	const DWORD dwWriteResult = WriteProcessMemory(this->handle, lpHandleAddress, &hLibrary, sizeof(HINSTANCE), nullptr);
	if (dwWriteResult == 0) {
		Log(xorstr_("FAILED TO WRITE MEMORY!!"));
		return false;
	}

	const HMODULE hModule = GetModuleHandleA(xorstr_("kernel32.dll"));
	if (hModule == INVALID_HANDLE_VALUE || hModule == nullptr) {
		Log(xorstr_("FAILED TO GET KERNEL32.DLL!!"));
		return false;
	}

	/* Get the LoadLibraryA address */
	const FARPROC lpFunctionAddress = GetProcAddress(hModule, xorstr_("FreeLibrary"));
	if (lpFunctionAddress == nullptr) {
		Log(xorstr_("FAILED TO GET FREELIBRARY!!"));
		return false;
	}

	/* Create the LoadLibraryA thread on the process */
	const HANDLE hThreadCreationResult = CreateRemoteThread(this->handle, nullptr, 0, (LPTHREAD_START_ROUTINE)lpFunctionAddress, lpHandleAddress, 0, nullptr);
	if (hThreadCreationResult == INVALID_HANDLE_VALUE || hThreadCreationResult == NULL) {
		Log(xorstr_("FAILED TO CREATEREMOTETHREAD!!"));
		return false;
	}

	/* Wait for thread to finish */
	WaitForSingleObject(hThreadCreationResult, INFINITE);
	CloseHandle(hThreadCreationResult);

	return true;
}

#pragma runtime_checks( "", off )
#pragma optimize( "", off )
void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData) {
	if (!pData) {
		pData->hMod = (HINSTANCE)0x404040;
		return;
	}

	BYTE* pBase = pData->pbase;
	auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;

	auto _LoadLibraryA = pData->pLoadLibraryA;
	auto _GetProcAddress = pData->pGetProcAddress;
#ifdef _WIN64
	auto _RtlAddFunctionTable = pData->pRtlAddFunctionTable;
#endif
	auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

	BYTE* LocationDelta = pBase - pOpt->ImageBase;
	if (LocationDelta) {
		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
			while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
				UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

				for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
					if (RELOC_FLAG(*pRelativeInfo)) {
						UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
					}
				}
				pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
			}
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name) {
			char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);

			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}
				else {
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
				}
			}
			++pImportDescr;
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
	}

	bool ExceptionSupportFailed = false;

#ifdef _WIN64

	if (pData->SEHSupport) {
		auto excep = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		if (excep.Size) {
			if (!_RtlAddFunctionTable(
				reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(pBase + excep.VirtualAddress),
				excep.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)pBase)) {
				ExceptionSupportFailed = true;
			}
		}
	}

#endif

	_DllMain(pBase, pData->fdwReasonParam, pData->reservedParam);

	if (ExceptionSupportFailed)
		pData->hMod = reinterpret_cast<HINSTANCE>(0x505050);
	else
		pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
}

PVOID Process::ManualMap(std::string const& dllPath, LPVOID lpReserved) const {
	/* Attempt to open dll file */
	std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
	if (!file.is_open()) {
		Log(xorstr_("Could not open dll ") << dllPath);
		return nullptr;
	}

	/* Get size of dll*/
	size_t fileSize = file.tellg();

	/* Rewind the file */
	file.seekg(0, std::ios::beg);
	
	/* Allocate a buffer with the size of the dll */
	auto buffer = std::make_unique<char[]>(fileSize);

	/* Read the dll into the buffer */
	if (!file.read(buffer.get(), fileSize)) {
		Log(xorstr_("Failed to read dll ") << dllPath);
		return nullptr;
	}

	/* Close the file */
	file.close();

	IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
	IMAGE_OPTIONAL_HEADER* pOldOptHeader = nullptr;
	IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
	BYTE* pTargetBase = nullptr;

	if (reinterpret_cast<IMAGE_DOS_HEADER*>(buffer.get())->e_magic != 0x5A4D) { //"MZ"
		Log(xorstr_("Invalid file"));
		return nullptr;
	}

	pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(buffer.get() + reinterpret_cast<IMAGE_DOS_HEADER*>(buffer.get())->e_lfanew);
	pOldOptHeader = &pOldNtHeader->OptionalHeader;
	pOldFileHeader = &pOldNtHeader->FileHeader;

	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64) {
		Log(xorstr_("Invalid platform"));
		return nullptr;
	}

	Log(xorstr_("File ok"));

	pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(this->handle, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!pTargetBase) {
		Log(xorstr_("Target process memory allocation failed (ex) 0x") << std::hex << GetLastError());
		return nullptr;
	}

	DWORD oldp = 0;
	VirtualProtectEx(this->handle, pTargetBase, pOldOptHeader->SizeOfImage, PAGE_EXECUTE_READWRITE, &oldp);

	MANUAL_MAPPING_DATA data{};
	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAddress = GetProcAddress;
#ifdef _WIN64
	data.pRtlAddFunctionTable = (f_RtlAddFunctionTable)RtlAddFunctionTable;
#else 
	SEHExceptionSupport = false;
#endif
	data.pbase = pTargetBase;
	data.fdwReasonParam = DLL_PROCESS_ATTACH;
	data.reservedParam = nullptr;
	data.SEHSupport = TRUE;


	//File header
	if (!WriteProcessMemory(this->handle, pTargetBase, buffer.get(), 0x1000, nullptr)) { //only first 0x1000 bytes for the header
		Log(xorstr_("Can't write file header 0x") << std::hex << GetLastError());
		VirtualFreeEx(this->handle, pTargetBase, 0, MEM_RELEASE);
		return nullptr;
	}

	IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
		if (pSectionHeader->SizeOfRawData) {
			if (!WriteProcessMemory(this->handle, pTargetBase + pSectionHeader->VirtualAddress, buffer.get() + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr)) {
				Log(xorstr_("Can't map sections: 0x") << std::hex << GetLastError());
				VirtualFreeEx(this->handle, pTargetBase, 0, MEM_RELEASE);
				return nullptr;
			}
		}
	}

	//Mapping params
	BYTE* MappingDataAlloc = reinterpret_cast<BYTE*>(VirtualAllocEx(this->handle, nullptr, sizeof(MANUAL_MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!MappingDataAlloc) {
		Log(xorstr_("Target process mapping allocation failed (ex) 0x") << std::hex << GetLastError());
		VirtualFreeEx(this->handle, pTargetBase, 0, MEM_RELEASE);
		return nullptr;
	}

	if (!WriteProcessMemory(this->handle, MappingDataAlloc, &data, sizeof(MANUAL_MAPPING_DATA), nullptr)) {
		Log(xorstr_("Can't write mapping 0x") << std::hex << GetLastError());
		VirtualFreeEx(this->handle, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(this->handle, MappingDataAlloc, 0, MEM_RELEASE);
		return nullptr;
	}

	//Shell code
	void* pShellcode = VirtualAllocEx(this->handle, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pShellcode) {
		Log(xorstr_("Memory shellcode allocation failed (ex) 0x") << std::hex << GetLastError());
		VirtualFreeEx(this->handle, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(this->handle, MappingDataAlloc, 0, MEM_RELEASE);
		return nullptr;
	}

	if (!WriteProcessMemory(this->handle, pShellcode, Shellcode, 0x1000, nullptr)) {
		Log(xorstr_("Can't write shellcode 0x") << std::hex << GetLastError());
		VirtualFreeEx(this->handle, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(this->handle, MappingDataAlloc, 0, MEM_RELEASE);
		VirtualFreeEx(this->handle, pShellcode, 0, MEM_RELEASE);
		return nullptr;
	}

	//Log(xorstr_("Mapped DLL at " << std::hex << pTargetBase);
	//Log(xorstr_("Mapping info at " << std::hex << MappingDataAlloc);
	//Log(xorstr_("Shell code at " << std::hex << pShellcode);

	//Log(xorstr_("Data allocated"));

	HANDLE hThread = CreateRemoteThread(this->handle, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), MappingDataAlloc, 0, nullptr);
	if (!hThread) {
		Log(xorstr_("Thread creation failed 0x") << std::hex << GetLastError());
		VirtualFreeEx(this->handle, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(this->handle, MappingDataAlloc, 0, MEM_RELEASE);
		VirtualFreeEx(this->handle, pShellcode, 0, MEM_RELEASE);
		return nullptr;
	}
	CloseHandle(hThread);

	Log(xorstr_("Thread created at: ") << std::hex << pShellcode << xorstr_(" waiting for return..."));

	HINSTANCE hCheck = NULL;
	while (!hCheck) {
		DWORD exitcode = 0;
		GetExitCodeProcess(this->handle, &exitcode);
		if (exitcode != STILL_ACTIVE) {
			Log(xorstr_("Process crashed, exit code: ") << exitcode);
			return nullptr;
		}

		MANUAL_MAPPING_DATA data_checked{ 0 };
		ReadProcessMemory(this->handle, MappingDataAlloc, &data_checked, sizeof(data_checked), nullptr);
		hCheck = data_checked.hMod;

		if (hCheck == (HINSTANCE)0x404040) {
			Log(xorstr_("Wrong mapping ptr"));
			VirtualFreeEx(this->handle, pTargetBase, 0, MEM_RELEASE);
			VirtualFreeEx(this->handle, MappingDataAlloc, 0, MEM_RELEASE);
			VirtualFreeEx(this->handle, pShellcode, 0, MEM_RELEASE);
			return nullptr;
		}
		else if (hCheck == (HINSTANCE)0x505050) {
			Log(xorstr_("WARNING: Exception support failed!"));
		}

		Sleep(10);
	}

	BYTE* emptyBuffer = (BYTE*)malloc(1024 * 1024 * 20);
	if (emptyBuffer == nullptr) {
		Log(xorstr_("Unable to allocate memory\n"));
		return nullptr;
	}
	memset(emptyBuffer, 0, 1024 * 1024 * 20);

	if (!WriteProcessMemory(this->handle, pTargetBase, emptyBuffer, 0x1000, nullptr)) {
		Log(xorstr_("WARNING!: Can't clear HEADER"));
	}

	pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
		if (pSectionHeader->Misc.VirtualSize) {
			if (strcmp((char*)pSectionHeader->Name, xorstr_(".rsrc")) == 0 ||
				strcmp((char*)pSectionHeader->Name, xorstr_(".reloc")) == 0) {
				Log(xorstr_("Processing ") << pSectionHeader->Name << xorstr_(" removal"));
				if (!WriteProcessMemory(this->handle, pTargetBase + pSectionHeader->VirtualAddress, emptyBuffer, pSectionHeader->Misc.VirtualSize, nullptr)) {
					Log(xorstr_("Can't clear section: ") << pSectionHeader->Name << " 0x" << std::hex << GetLastError());
				}
			}
		}
	}

	pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
		if (pSectionHeader->Misc.VirtualSize) {
			DWORD old = 0;
			DWORD newP = PAGE_READONLY;

			if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) > 0) {
				newP = PAGE_READWRITE;
			}
			else if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0) {
				newP = PAGE_EXECUTE_READ;
			}
			if (VirtualProtectEx(this->handle, pTargetBase + pSectionHeader->VirtualAddress, pSectionHeader->Misc.VirtualSize, newP, &old)) {
				Log(xorstr_("section ") << (char*)pSectionHeader->Name << xorstr_(" set as ") << newP);
			}
			else {
				Log(xorstr_("error: section ") << (char*)pSectionHeader->Name << xorstr_("not set as ") << newP);
			}
		}
	}
	DWORD old = 0;
	VirtualProtectEx(this->handle, pTargetBase, IMAGE_FIRST_SECTION(pOldNtHeader)->VirtualAddress, PAGE_READONLY, &old);

	if (!WriteProcessMemory(this->handle, pShellcode, emptyBuffer, 0x1000, nullptr)) {
		Log(xorstr_("WARNING: Can't clear shellcode"));
	}
	if (!VirtualFreeEx(this->handle, pShellcode, 0, MEM_RELEASE)) {
		Log(xorstr_("WARNING: can't release shell code memory"));
	}
	if (!VirtualFreeEx(this->handle, MappingDataAlloc, 0, MEM_RELEASE)) {
		Log(xorstr_("WARNING: can't release mapping data memory"));
	}

	return pTargetBase;
}

bool Process::ManualFree(std::string const& dllPath, PVOID address) const {
	/* Attempt to open dll file */
	std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
	if (!file.is_open()) {
		Log(xorstr_("Could not open dll ") << dllPath);
		return false;
	}

	/* Get size of dll*/
	size_t fileSize = file.tellg();

	/* Close the file */
	file.close();

	/* Change the protection to allow VirtualFreeEx to be called */
	DWORD oldProtect;
	if (!VirtualProtectEx(this->handle, address, fileSize, PAGE_READWRITE, &oldProtect)) {
		Log(xorstr_("Failed to change DLL memory protection 0x") << std::hex << GetLastError());
		return false;
	}

	/* Free the dll from memory */
	if (!VirtualFreeEx(this->handle, address, 0, MEM_RELEASE)) {
		Log(xorstr_("Failed to free DLL from memory 0x") << std::hex << GetLastError());
		return false;
	}
	return true;
}