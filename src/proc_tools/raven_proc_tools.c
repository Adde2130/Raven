#include "raven_proc_tools.h"
#include "raven_memory.h"
#include "raven_debug.h"
#include "raven_windows_internal.h"
#include "raven_util.h"

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

/**
 * @brief Internally used wrapper for LoadLibrary in order to avoid compiler warnings
 * 
 */
DWORD WINAPI LoadLibraryWrapper(LPVOID lpParam) {
    LPCTSTR lpFileName = (LPCTSTR)lpParam;
    if (lpFileName == NULL) {
        return 1; // Error: Invalid parameter
    }
    HMODULE hModule = LoadLibrary(lpFileName);
    if (hModule == NULL) {
        return 2; // Error: Failed to load library
    }
    return 0;
}

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

        HANDLE hThread = CreateRemoteThread(hProc, 0, 0, LoadLibraryWrapper, loc, 0, 0);
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

int8_t hijack_entry_point(const char* executable, int argc, const char** argv, const char* current_dir, EntryData* entrydata, RAVEN_PROCESS_INFO* extended_info) {
    PROCESS_INFORMATION procinfo;
    STARTUPINFO startinfo;

    ZeroMemory(&startinfo, sizeof(startinfo));
    startinfo.cb = sizeof(startinfo);
    ZeroMemory(&procinfo, sizeof(procinfo));

    char cmdLine[512];
    sprintf(cmdLine, "\"%s\"", executable);
    if(argv != NULL)
        for(int i = 0; i < argc; i++)
            sprintf(cmdLine + strlen(cmdLine), " %s", argv[i]);
    

    if (!CreateProcess(NULL, cmdLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, current_dir, &startinfo, &procinfo) || procinfo.hProcess == INVALID_HANDLE_VALUE || !procinfo.hProcess) {
        return 1;
    }

    find_entry_point(executable, &entrydata->entry);
    char selfjump[2] = {0xEB, 0xFE};

    /* Get the base address of the loaded module */
    PROCESS_BASIC_INFORMATION pbi;
    ULONG bytesReturned;
    PEB peb;
    SIZE_T bytesRead;

    NTSTATUS status;    
    status = NtQueryInformationProcess(procinfo.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &bytesReturned);
    if(status != 0) { // STATUS_SUCCESS = 0
        return 2;
    }

    WINBOOL success;
    success = ReadProcessMemory(procinfo.hProcess, pbi.PebBaseAddress, &peb, sizeof(PEB), &bytesRead);
    if(!success) {
        return 3;
    }
    
    *(uintptr_t*)(&entrydata->entry) += (uintptr_t)peb.ImageBaseAddress;

    /* RE-ENABLE IF SOMETHING BREAKS */
//     /* This is supposed to hold the base address but it may change due to windows updates :/ */
// #ifndef _WIN64
//     *(uintptr_t*)(&entrydata->entry) += *(uintptr_t*)((char*)(&peb) + 0x8);
// #else
//     *(uintptr_t*)(&entrydata->entry) += *(uintptr_t*)((char*)(&peb) + 0x10);
// #endif

    ReadProcessMemory(procinfo.hProcess, entrydata->entry, entrydata->bytes, 2, NULL);
    WriteProcessMemory(procinfo.hProcess, entrydata->entry, selfjump, 2, NULL);

    ResumeThread(procinfo.hThread);

    if(extended_info != NULL) {
        extended_info->si  = startinfo;
        extended_info->pi  = procinfo;
        extended_info->pbi = pbi;
        extended_info->peb = peb;
    } else {
        CloseHandle(procinfo.hProcess);
        CloseHandle(procinfo.hThread);
    }

    return 0;
}

void hijack_entry_point_ex(const char* executable, HANDLE hProcess, EntryData* entrydata) {
    find_entry_point(executable, &entrydata->entry);
    char selfjump[2] = {0xEB, 0xFE};

    ReadProcessMemory(hProcess, entrydata->entry, entrydata->bytes, 2, NULL);
    WriteProcessMemory(hProcess, entrydata->entry, selfjump, 2, NULL);

    CloseHandle(hProcess);
}

void repair_entry(EntryData* data){
    protected_write(data->entry, data->bytes, 2);
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
#ifndef _WIN64
    PIMAGE_NT_HEADERS32 ntHeader = (PIMAGE_NT_HEADERS32)(lpBase + dosHeader->e_lfanew);
#else
    PIMAGE_NT_HEADERS64 ntHeader = (PIMAGE_NT_HEADERS64)(lpBase + dosHeader->e_lfanew);
#endif

    if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
        return 6;

    uintptr_t pEntryPoint = ntHeader->OptionalHeader.AddressOfEntryPoint;
    *entrypoint = (void*) pEntryPoint;

    UnmapViewOfFile((LPCVOID)lpBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    return 0;
}

void* GetModuleFunction(const char* lib, const char* function_name){
    return GetProcAddress(GetModuleHandle(lib), function_name);
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

bool is_wow64(HANDLE hProcess) {
    BOOL bIsWow64 = false;

    SYSTEM_INFO si = {0};
    GetNativeSystemInfo(&si);
    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 || si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64)
        IsWow64Process(hProcess, &bIsWow64);

    return bIsWow64;
}

bool remove_from_loaded_modules(const char* dllname){
    PPEB peb = GetPEB();

    LIST_ENTRY* first_module = PTROFFSET(peb->Ldr->InMemoryOrder.Flink, -sizeof(LIST_ENTRY));
    for(LIST_ENTRY* module = first_module->Flink; module && module != first_module; module = module->Flink) {
        LDR_DATA_TABLE_ENTRY* moduleEntry = (LDR_DATA_TABLE_ENTRY*) module;
        char msg[MAX_PATH];
        wcstombs(msg, moduleEntry->FullDllName.Buffer, sizeof(msg));
        if(strcmp(dllname, msg) == 0) {
            patch_linked_list(&moduleEntry->InLoadOrder, false);
            patch_linked_list(&moduleEntry->InMemOrder, false);
            patch_linked_list(&moduleEntry->InInitOrder, false);
            return true;
        }
    }

    return false;
}

HANDLE module_from_address(void* address){
    HMODULE hModule = NULL;
    DWORD cbNeeded;
    HANDLE hProcess = GetCurrentProcess();

    HMODULE* hModuleArray = (HMODULE*)malloc(cbNeeded);
    if (!hModuleArray) 
        return NULL;
    
    if (!EnumProcessModules(hProcess, hModuleArray, cbNeeded, &cbNeeded)) {
        free(hModuleArray);
        return NULL;
    }

    for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
        MODULEINFO moduleInfo;
        if (!GetModuleInformation(hProcess, hModuleArray[i], &moduleInfo, sizeof(MODULEINFO))) 
            continue;

        if ((uintptr_t)address >= (uintptr_t)moduleInfo.lpBaseOfDll &&
            (uintptr_t)address < ((uintptr_t)moduleInfo.lpBaseOfDll + moduleInfo.SizeOfImage)) {
            hModule = hModuleArray[i];
            break;
        }
    }

    return hModule;
}
