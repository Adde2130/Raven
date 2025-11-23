#include "raven_inject.h"
#include "raven_windows_internal.h"

#include <TlHelp32.h>
#include <winternl.h>
#include <Psapi.h>
#include <stdio.h>
#include <shlwapi.h>
#include <inttypes.h>

bool inject_dll(const char* dllname, int pid){
    char dllpath[MAX_PATH] = {0};
    GetFullPathName(dllname, MAX_PATH, dllpath, NULL);

    /* Check that the file actually exists */
    FILE *file = fopen(dllname, "r");
    if (!file)
        return false;
    fclose(file);

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);

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

        HANDLE hThread = CreateRemoteThread(hProc, 0, 0, (void*)LoadLibrary, loc, 0, 0);
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

uint8_t inject_dll_ex(const char* dllname, int pid, RavenInjectionData* data, size_t datasize) {
    char dllpath[MAX_PATH] = {0};
    GetFullPathName(dllname, MAX_PATH, dllpath, NULL);

    /* Check that the file actually exists */
    FILE *file = fopen(dllname, "r");
    if (!file)
        return 1;
    fclose(file);

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);

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

    HMODULE hDll = LoadLibrary(dllname);
    if(hDll == NULL)
        return 7;

    FARPROC RavenLoaderAddress = GetProcAddress(hDll, "RavenLoader");
    if(RavenLoaderAddress == NULL) {
        /* In case of name mangling */
        RavenLoaderAddress = GetProcAddress(hDll, "RavenLoader@4"); 
        if(RavenLoaderAddress == NULL) {
            FreeLibrary(hDll);
            return 8;
        }
    }

    HANDLE LoadLibraryThread = CreateRemoteThread(hProc, 0, 0, (void*) LoadLibraryA, dllpathloc, 0, 0);
    if(!LoadLibraryThread || LoadLibraryThread == INVALID_HANDLE_VALUE){
        FreeLibrary(hDll);
        VirtualFreeEx(hProc, dllpathloc, strlen(dllpath) + 1, MEM_RELEASE);
        return 9;
    }
    WaitForSingleObject(LoadLibraryThread, INFINITE);

#ifndef _WIN64
    DWORD hInjectedDll;
    success = GetExitCodeThread(LoadLibraryThread, &hInjectedDll);
    if(!success || !hInjectedDll) {
        FreeLibrary(hDll);
        return 10;
    }
#else
    // Since threads created with CreateRemoteThread only return 32-bit values, we need a
    // workaround to get the base of the dll in 64-bit...
    uint64_t hInjectedDll = 0;
    HMODULE modules[64];
    BOOL module_info_success;
    DWORD modules_size;
    module_info_success = EnumProcessModules(hProc, modules, sizeof(modules), &modules_size);
    if(!module_info_success)
        return 11;
    
    char module_name[MAX_PATH];
    for (uint64_t i = 0; i < (modules_size / sizeof(HMODULE)); i++) {
        module_info_success = GetModuleFileNameEx(hProc, modules[i], module_name, sizeof(module_name));
        if(!module_info_success)
            continue;

        if(strcmp(module_name, dllpath))
            continue;


        MODULEINFO module_info;
        module_info_success = GetModuleInformation(hProc, modules[i], &module_info, sizeof(module_info));
        if(!module_info_success)
            continue;

        hInjectedDll = (uint64_t)module_info.lpBaseOfDll;

        break;
    }

    if(!hInjectedDll)
        return 12;
#endif

    data->mData.hModule = (HANDLE)hInjectedDll;
    data->mData.dllname = dllpathloc;
    
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

    CloseHandle(LoadLibraryThread);

    uintptr_t dwFunctionOffset = (uintptr_t)RavenLoaderAddress - (uintptr_t)hDll + (uintptr_t)hInjectedDll;
    FreeLibrary(hDll);

    HANDLE RavenLoaderThread = CreateRemoteThread(hProc, 0, 0, (void*)dwFunctionOffset, data_loc, 0, 0);
    if(!RavenLoaderThread || RavenLoaderThread == INVALID_HANDLE_VALUE) {
        CloseHandle(hProc);
        return 13;
    } 

    WaitForSingleObject(RavenLoaderThread, INFINITE);
    CloseHandle(RavenLoaderThread);
    VirtualFreeEx(hProc, data_loc, datasize, MEM_RELEASE);

    CloseHandle(hProc);

    return 0;
}
