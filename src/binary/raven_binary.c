#include "raven_binary.h"
#include "raven_memory.h"
#include "raven_assembly.h"
#include "raven_debug.h"
#include "raven_proc_tools.h"

#include <stdio.h>
#include <Psapi.h>

void create_detour(void* dest, void* patch, uint32_t leftover_bytes){
    const int jmp_length = 5; // JMP instruction bytes
    int patch_length = jmp_length + leftover_bytes;
    uintptr_t offset = ((uintptr_t)patch - (uintptr_t)dest) - jmp_length;
    byte* patch_bytes = malloc(sizeof(byte) * patch_length);
    memset(patch_bytes, NOP, patch_length);
    patch_bytes[0] = 0xe8;
    memcpy(patch_bytes + 1, &offset, jmp_length - 1);
    write_bytes(dest, patch_bytes, patch_length);
    free(patch_bytes);
}

void* find_code_cave(const size_t desired_size, HANDLE hModule, void* address) {
    if(!desired_size || (!hModule && !address))
        return NULL;

    if(!hModule)
        hModule = module_from_address(address);


    HANDLE hProcess = GetCurrentProcess();

    MEMORY_BASIC_INFORMATION memInfo;
    DWORD oldprotect;

    PIMAGE_DOS_HEADER dosHeader = (IMAGE_DOS_HEADER*)hModule;
    PIMAGE_NT_HEADERS ntHeader = (IMAGE_NT_HEADERS*)((BYTE*)hModule + dosHeader->e_lfanew);

    uintptr_t moduleBase = ntHeader->OptionalHeader.ImageBase;
    uintptr_t moduleCodeOffset = (uintptr_t)PTROFFSET(ntHeader->OptionalHeader.BaseOfCode, moduleBase);
    uintptr_t moduleCodeSize = (uintptr_t)ntHeader->OptionalHeader.SizeOfCode;

    void* memRegion;
    if(address && (void*)moduleCodeOffset < PTROFFSET(address, -2147483648))
        memRegion = PTROFFSET(address, -2147483648);
    else
        memRegion = (void*)moduleCodeOffset;

    void* memLimit;
    if(address && PTROFFSET(moduleCodeOffset, moduleCodeSize) > PTROFFSET(address, 2147483647))
        memLimit = PTROFFSET(address, 2147483647);
    else
        memLimit = PTROFFSET(moduleCodeOffset, moduleCodeSize);

    /* In the case that the first VirtualQueryEx fails */
    memInfo.RegionSize = 512;

    for(; memRegion < memLimit; memRegion = PTROFFSET(memInfo.BaseAddress, memInfo.RegionSize)) {
        if(!VirtualQueryEx(hProcess, memRegion, &memInfo, sizeof(memInfo)))
            continue;

        if(memInfo.State != MEM_COMMIT)
            continue;

        oldprotect = 0;
        if(memInfo.Protect != PAGE_EXECUTE_READWRITE) {
            if(!(memInfo.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ)))
                continue;


            if(!VirtualProtect(memRegion, memInfo.RegionSize, PAGE_EXECUTE_READWRITE, &oldprotect))
                continue;
        }

        size_t cave_canditate_size = 0;
        void* cave_canditate = NULL;
        for(uint64_t i = 0; i < memInfo.RegionSize; i++) {
            unsigned char* byte = PTROFFSET(memRegion, i); 
            if(ISGARBAGE(*byte)) { 
                if(cave_canditate_size == 0)
                    cave_canditate = byte;
                cave_canditate_size++;
                if(cave_canditate_size == desired_size) {
                    VirtualProtect(memRegion, memInfo.RegionSize, oldprotect, &oldprotect);
                    return cave_canditate;
                }
            } else {
                cave_canditate_size = 0;
                cave_canditate = NULL;
            }
        }

        VirtualProtect(memRegion, memInfo.RegionSize, oldprotect, &oldprotect);

    }

    return NULL;

}
