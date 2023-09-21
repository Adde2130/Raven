#include "raven_proc_tools.h"
#include "raven_memory.h"
#include "raven_debug.h"
#include <TlHelp32.h>
#include <winternl.h>
#include <Psapi.h>
#include <stdio.h>
#include <shlwapi.h>
#include <inttypes.h>

NTSTATUS NTAPI NtQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

DWORD get_process_id(const char* target){
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(!snap || snap == INVALID_HANDLE_VALUE) 
        return 0;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(pe32);
    if(Process32First(snap, &pe32)){
        do{
            if(!_stricmp(pe32.szExeFile, target)){
                CloseHandle(snap);
                return pe32.th32ProcessID;
            }
        } while(Process32Next(snap, &pe32));
    }

    return 0;
}

bool inject_dll(const char* dllname, int pid){
    char dllpath[MAX_PATH] = {0};
    GetFullPathName(dllname, MAX_PATH, dllpath, NULL);

    /* Check that the file actually exists */
    FILE *file = fopen(dllname, "r");
    if (!file)
        return false;
    fclose(file);

    HANDLE hProc= OpenProcess(PROCESS_ALL_ACCESS, 0, pid);

    if(hProc && hProc != INVALID_HANDLE_VALUE) {
        void* loc = VirtualAllocEx(hProc, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if(!loc) {
            CloseHandle(hProc);
            return false;
        }

        bool success = WriteProcessMemory(hProc, loc, dllpath, strlen(dllpath) + 1, 0);
        if(!success) {
            CloseHandle(hProc);
            return false;
        }

        HANDLE hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, loc, 0, 0);
        if(!hThread || hThread == INVALID_HANDLE_VALUE) {
            CloseHandle(hProc);
            return false;
        }
            

        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);

    }

    CloseHandle(hProc);
    return true;
}

uint8_t inject_dll_ex(const char* dllname, int pid, void* data, size_t datasize){
    char dllpath[MAX_PATH] = {0};
    GetFullPathName(dllname, MAX_PATH, dllpath, NULL);

    /* Check that the file actually exists */
    FILE *file = fopen(dllname, "r");
    if (!file)
        return 1;
    fclose(file);

    HANDLE hProc= OpenProcess(PROCESS_ALL_ACCESS, 0, pid);

    if(!hProc || hProc == INVALID_HANDLE_VALUE) {
        return 2;
    }

    void* dllpathloc = VirtualAllocEx(hProc, 0, strlen(dllpath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if(!dllpathloc) {
        CloseHandle(hProc);
        return 3;
    }

    bool success = WriteProcessMemory(hProc, dllpathloc, dllpath, strlen(dllpath) + 1, 0);
    if(!success) {
        CloseHandle(hProc);
        return 4;
    }

    void* data_loc = VirtualAllocEx(hProc, 0, datasize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if(!data_loc){
        CloseHandle(hProc);
        return 5;
    }

    success = WriteProcessMemory(hProc, data_loc, data, datasize, 0);
    if(!success) {
        CloseHandle(hProc);
        return 6;
    }

    HMODULE hLocalModule = LoadLibrary(dllname);
    if(hLocalModule == NULL)
        return 7;

    FARPROC hLocalFunction = GetProcAddress(hLocalModule, "RavenLoader");
    if(hLocalFunction == NULL) {
        /* In case of name mangling */
        hLocalFunction = GetProcAddress(hLocalModule, "RavenLoader@4"); 
        if(hLocalFunction == NULL) {
            FreeLibrary(hLocalModule);
            return 8;
        }
    }

    FARPROC hLoadLibrary = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    if(!hLoadLibrary) {
        FreeLibrary(hLocalModule);
        return 9;
    }

    HANDLE hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)hLoadLibrary, dllpathloc, 0, 0);
    if(!hThread || hThread == INVALID_HANDLE_VALUE){
        FreeLibrary(hLocalModule);
        return 10;
    }
    WaitForSingleObject(hThread, INFINITE);

    DWORD hRemoteModule;
    GetExitCodeThread(hThread, &hRemoteModule);
    if(hRemoteModule == 0) {
        FreeLibrary(hLocalModule);
        return 11;
    }
    CloseHandle(hThread);

    uintptr_t dwFunctionOffset = (uintptr_t)hLocalFunction - (uintptr_t)hLocalModule + (uintptr_t)hRemoteModule;
    FreeLibrary(hLocalModule);

    hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)dwFunctionOffset, data_loc, 0, 0);
    if(!hThread || hThread == INVALID_HANDLE_VALUE) {
        CloseHandle(hProc);
        return 11;
    } 

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    CloseHandle(hProc);
    return 0;
}

int8_t hijack_entry_point(const char* executable, int argc, char** argv, uintptr_t* p_entrypoint, char* original_bytes) {
    PROCESS_INFORMATION procinfo;
    STARTUPINFO startinfo;

    ZeroMemory(&startinfo, sizeof(startinfo));
    startinfo.cb = sizeof(startinfo);
    ZeroMemory(&procinfo, sizeof(procinfo));

    char cmdLine[512];
    sprintf(cmdLine, "\"%s\"", executable);
    for(int i = 0; i < argc; i++)
        sprintf(cmdLine + strlen(cmdLine), " %s", argv[i]);

    if (!CreateProcess(NULL, cmdLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startinfo, &procinfo) || procinfo.hProcess == INVALID_HANDLE_VALUE || !procinfo.hProcess) {
        return 1;
    }

    void* entrypoint;
    find_entry_point(executable, &entrypoint);
    char selfjump[2] = {0xEB, 0xFE};

    ReadProcessMemory(procinfo.hProcess, (void*) entrypoint, original_bytes, 2, NULL);
    WriteProcessMemory(procinfo.hProcess, (void*) entrypoint, selfjump, 2, NULL);
    *p_entrypoint = (uintptr_t)entrypoint;

    ResumeThread(procinfo.hThread);
    CloseHandle(procinfo.hProcess);
    CloseHandle(procinfo.hThread);

    return 0;
}

uint32_t find_entry_point(const char* executable, void** entrypoint){
    BY_HANDLE_FILE_INFORMATION bhfi;
    HANDLE hMapping;
    char *lpBase;
    HANDLE hFile = CreateFile(executable, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return 1;

    if (!GetFileInformationByHandle(hFile, &bhfi))
        return 2;

    hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, bhfi.nFileSizeHigh, bhfi.nFileSizeLow, NULL);
    if (!hMapping)
        return 3;
    lpBase = (char *)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, bhfi.nFileSizeLow);
    if (!lpBase)
        return 4;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)lpBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return 5;

    PIMAGE_NT_HEADERS32 ntHeader = (PIMAGE_NT_HEADERS32)(lpBase + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
        return 6;

    uintptr_t pEntryPoint = ntHeader->OptionalHeader.ImageBase + ntHeader->OptionalHeader.AddressOfEntryPoint;
    *entrypoint = (void*) pEntryPoint;

    UnmapViewOfFile((LPCVOID)lpBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    return 0;
}

bool is_module_loaded(HANDLE process, const char* module_name, HMODULE* module){
    HMODULE modules[256] = {0};
    if(!EnumProcessModules(process, modules, sizeof(modules), NULL))
        return false;
    for(int i = 0; i < 256; i++) {
        HMODULE mod = modules[i];
        char mod_name[MAX_PATH];
        char* dllname;

        if(GetModuleFileName(mod, mod_name, sizeof(mod_name) / sizeof(char))) {
            dllname = PathFindFileName(mod_name);
            if(strcmp(module_name, dllname) == 0) {
                *module = mod;
                return true;
            }
        }
    }

    return false;
}

bool is_wow64(HANDLE hProcess)
{
    BOOL bIsWow64 = false;

    SYSTEM_INFO si = {0};
    GetNativeSystemInfo(&si);
    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 || si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64)
        IsWow64Process(hProcess, &bIsWow64);

    return bIsWow64;
}