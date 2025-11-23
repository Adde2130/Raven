#include "raven_memory.h"
#include "raven_debug.h"
#include <intrin.h>

#define MEMBLOCK_SIZE 0x1000
#define MAX_MEMORY_RANGE 0x40000000


typedef struct _MEMBLOCK {
    struct _MEMBLOCK* next;
    size_t bytes_used;
} MEMBLOCK;

MEMBLOCK* MEMBLOCK_HEAD = NULL;

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

void* find_unallocated_memory(void* base, size_t size) {
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

    max_addr = PTROFFSET(max_addr, -MEMBLOCK_SIZE + 1);

    MEMBLOCK* memblock = NULL;
    MEMBLOCK* last_memblock = NULL;
    if(MEMBLOCK_HEAD) {
        for(last_memblock = MEMBLOCK_HEAD; last_memblock->next; last_memblock = last_memblock->next){
            if(MEMBLOCK_SIZE - last_memblock->bytes_used < size)
                continue;

            memblock = PTROFFSET(last_memblock, last_memblock->bytes_used);
            if((uintptr_t)memblock < (uintptr_t)min_addr || (uintptr_t)memblock > (uintptr_t)max_addr)
                continue;

            last_memblock->bytes_used += size;
            return memblock;
        }
    }

    void* curr_addr = base;
    while (curr_addr >= min_addr) {
        curr_addr = __find_prev_mem_region(curr_addr, min_addr, si.dwAllocationGranularity);
        if (curr_addr == NULL)
            break;

        memblock = VirtualAlloc(curr_addr, MEMBLOCK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (memblock)        
            goto INIT_MEMBLOCK;
    }

    curr_addr = base;
    while (curr_addr <= max_addr) {
        curr_addr = __find_next_mem_region(curr_addr, max_addr, si.dwAllocationGranularity);
        if (curr_addr == NULL)
                break;

        memblock = VirtualAlloc(curr_addr, MEMBLOCK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (memblock)
            goto INIT_MEMBLOCK;
    }

    return NULL;

INIT_MEMBLOCK:
    if(last_memblock)
        last_memblock->next = memblock;
    
    memblock->next = NULL;
    memblock->bytes_used = sizeof(MEMBLOCK*) + sizeof(size_t) + size;
    return PTROFFSET(memblock, memblock->bytes_used);
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

void raven_nop(void* dest, uint32_t count) {
	const uint8_t NOP = 0x90;
	for(uint32_t i = 0; i < count; i++) 
		protected_write(PTROFFSET(dest, i), &NOP, 1);
}

void raven_write8(void* dest, uint8_t value) {
	protected_write(dest, &value, 1);
}

void raven_write16(void* dest, uint16_t value) {
	protected_write(dest, &value, 2);
}

void raven_write32(void* dest, uint32_t value) {
	protected_write(dest, &value, 4);
}
