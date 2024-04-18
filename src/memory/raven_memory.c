#include "raven_memory.h"
#include "raven_debug.h"
#include <intrin.h>

bool pointer_valid(void* ptr, uint32_t size) {
    if(ptr == NULL) return false;
    MEMORY_BASIC_INFORMATION mbi = {0};
    if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0)
        return false; 
        
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD | PAGE_READONLY))
        return false;

    uintptr_t pInt = (uintptr_t)ptr;
    uintptr_t region_end = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    if ((pInt + size) > region_end)
        return false; 

    return true;
}

uint8_t trace_pointer(const mem_ptr* p_mem_ptr, void** ptr){
    uintptr_t* location = (uintptr_t*)((uintptr_t)GetModuleHandle(NULL) + (uintptr_t)p_mem_ptr->base_address);
    for(int i = 0; i < p_mem_ptr->total_offsets; i++) {
        if(location == NULL)
            return 1;
        if(!pointer_valid(location, sizeof(uintptr_t)))
            return 2;

        location = (uintptr_t*)(*location + p_mem_ptr->offsets[i]);
    }

    if(!pointer_valid(location, sizeof(uintptr_t)))
        return 2;

    *ptr = location;
    return 0;
}

void* __find_prev_mem_region(void* base, void* min_addr, DWORD granularity) {
    uintptr_t curr_addr = (uintptr_t)base;

    curr_addr -= curr_addr % granularity;
    curr_addr -= granularity;

    while (curr_addr >= (uintptr_t)min_addr)
    {
        MEMORY_BASIC_INFORMATION memInfo;
        if (VirtualQuery((void*)curr_addr, &memInfo, sizeof(memInfo)) == 0)
            break;

        if (memInfo.State == MEM_FREE)
            return (void*)curr_addr;

        if ((uintptr_t)memInfo.AllocationBase < granularity)
            break;

        curr_addr = (uintptr_t)memInfo.AllocationBase - granularity;
    }

    return NULL;
}

void* __find_next_mem_region(void* base, void* max_addr, DWORD granularity) {
    uintptr_t curr_addr = (uintptr_t)base;

    curr_addr -= curr_addr % granularity;
    curr_addr += granularity;

    while (curr_addr <= (uintptr_t)max_addr)
    {
        MEMORY_BASIC_INFORMATION memInfo;
        if (VirtualQuery((void*)curr_addr, &memInfo, sizeof(memInfo)) == 0)
            break;

        if (memInfo.State == MEM_FREE)
            return (void*)curr_addr;

        curr_addr = (uintptr_t)memInfo.BaseAddress + memInfo.RegionSize;

        curr_addr += granularity - 1;
        curr_addr -= curr_addr % granularity;
    }

    return NULL;
}

void* find_unallocated_memory(void* base) {
    void* min_addr;
    void* max_addr;

    SYSTEM_INFO si;
    GetSystemInfo(&si);

    min_addr = si.lpMinimumApplicationAddress;
    max_addr = si.lpMaximumApplicationAddress;

    if(base > (void*)MAX_MEMORY_RANGE && min_addr > PTROFFSET(base, -MAX_MEMORY_RANGE))
        min_addr = PTROFFSET(base, -MAX_MEMORY_RANGE);

    if(max_addr > PTROFFSET(base, MAX_MEMORY_RANGE))
        max_addr = PTROFFSET(base, MAX_MEMORY_RANGE);

    max_addr = PTROFFSET(max_addr, -MEMORY_BLOCK_SIZE + 1);

    void* curr_addr = base;
    while (curr_addr >= min_addr) {
        curr_addr = __find_prev_mem_region(curr_addr, min_addr, si.dwAllocationGranularity);
        if (curr_addr == NULL)
            break;

        void* memblock = VirtualAlloc(curr_addr, MEMORY_BLOCK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (memblock != NULL)        
            return memblock;
    }

    curr_addr = base;
    while (curr_addr <= max_addr) {
        curr_addr = __find_next_mem_region(curr_addr, max_addr, si.dwAllocationGranularity);
        if (curr_addr == NULL)
                break;

        void* memblock = VirtualAlloc(curr_addr, MEMORY_BLOCK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (memblock != NULL)
            return memblock;
    }

    return NULL;
    
}

void protected_write(void* dest, const void* src, int len){
    DWORD old_protect;
    VirtualProtect(dest, len, PAGE_EXECUTE_READWRITE, &old_protect);
    memcpy(dest, src, len);
    VirtualProtect(dest, len, old_protect, &old_protect);
}

void read_bytes(void* src, void* read_buffer, int len){
    protected_write(read_buffer, src, len);
}

void write_bytes(void* src, void* dest, int len){
    protected_write(dest, src, len);
}

void protected_fill_bytes(void* dest, const char byte, const int len) {
    DWORD old_protect;
    VirtualProtect(dest, len, PAGE_EXECUTE_READWRITE, &old_protect);
    for(int i = 0; i < len; i++)
        memcpy((char*)dest + i, &byte, 1);
    VirtualProtect(dest, len, old_protect, &old_protect);
}

void patch(mem_patch* patch) {
    protected_write(patch->original_bytes, patch->address, patch->size);
    protected_write(patch->address, patch->patch_bytes, patch->size);
}
