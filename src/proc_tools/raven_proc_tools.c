#include "raven_proc_tools.h"
#include "raven_memory.h"
#include <TlHelp32.h>
#include <winternl.h>
#include <Psapi.h>
#include <stdio.h>
#include <shlwapi.h>
#include <inttypes.h>

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

int8_t hijack_entry_point(const char* executable, uintptr_t* p_entrypoint, char* original_bytes) {
    PROCESS_INFORMATION procinfo;
    STARTUPINFO startinfo;
    IMAGE_DOS_HEADER dosHeader;
#ifdef _WIN64
    IMAGE_NT_HEADERS64 ntHeaders;
#else
    IMAGE_NT_HEADERS   ntHeaders;
#endif

    ZeroMemory(&startinfo, sizeof(startinfo));
    startinfo.cb = sizeof(startinfo);
    ZeroMemory(&procinfo, sizeof(procinfo));

    char cmdLine[MAX_PATH];
    sprintf(cmdLine, "\"%s\"", executable);
    if (!CreateProcess(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &startinfo, &procinfo) || procinfo.hProcess == INVALID_HANDLE_VALUE || !procinfo.hProcess) {
        return 1;
    }

    HMODULE hModules[1024] = {0};
    DWORD cbNeeded;

    // This is the dumbest shit I have ever come up with but I am desperate, have been sitting 8 hours with this
    // I fucking despise this with my entire soul, TODO: FIX THIS PLEASE
    while(!EnumProcessModules(procinfo.hProcess, hModules, sizeof(hModules), &cbNeeded)) {
        Sleep(2);
        ZeroMemory(hModules, sizeof(hModules));
    }
    SuspendThread(procinfo.hThread);

    // if (!EnumProcessModules(procinfo.hProcess, hModules, sizeof(hModules), &cbNeeded)) {
    //     printf("ERROR getting module handle: %lu\n", GetLastError());
    //     CloseHandle(procinfo.hProcess);
    //     CloseHandle(procinfo.hThread);
    //     return 2;
    // }

    HMODULE hMainExecutable = hModules[0];

    if (!ReadProcessMemory(procinfo.hProcess, hMainExecutable, &dosHeader, sizeof(dosHeader), NULL)) {
        printf("ERROR readding process memory: %lu\n", GetLastError());
        CloseHandle(procinfo.hProcess);
        CloseHandle(procinfo.hThread);
        return 3;
    }

    if (!ReadProcessMemory(procinfo.hProcess, (BYTE*)hMainExecutable + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders), NULL)) {
        CloseHandle(procinfo.hProcess);
        CloseHandle(procinfo.hThread);
        return 4;
    }


    uintptr_t entrypoint = (uintptr_t)hMainExecutable + ntHeaders.OptionalHeader.AddressOfEntryPoint;
    char selfjump[2] = {0xEB, 0x00};

    ReadProcessMemory(procinfo.hProcess, (void*) entrypoint, original_bytes, 2, NULL);
    WriteProcessMemory(procinfo.hProcess, (void*) entrypoint, selfjump, 2, NULL);

    *p_entrypoint = entrypoint;

    ResumeThread(procinfo.hThread);
    CloseHandle(procinfo.hProcess);
    CloseHandle(procinfo.hThread);

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