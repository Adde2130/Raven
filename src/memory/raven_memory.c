#include "raven_memory.h"

bool pointer_valid(void* ptr, uint32_t size) {
    MEMORY_BASIC_INFORMATION mbi = {0};
    if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0)
        return false; 
        
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))
        return false;

    uintptr_t pInt = (uintptr_t)ptr;
    uintptr_t region_end = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    if ((pInt + size) > region_end)
        return false; 

    return true;
}

void* trace_pointer(mem_ptr* p_mem_ptr){
    uintptr_t* location = (uintptr_t*)((uintptr_t)GetModuleHandle(NULL) + (uintptr_t)p_mem_ptr->base_address);
    for(int i = 0; i < p_mem_ptr->total_offsets; i++) {
        if(location == NULL || !pointer_valid(location, sizeof(uintptr_t)))
            return NULL;

        location = (uintptr_t*)(*location + p_mem_ptr->offsets[i]);
    }

    if(!pointer_valid(location, sizeof(uintptr_t)))
        return NULL;

    return location;
}

void protected_read(void* dest, void* src, int len){
    DWORD old_protect;
    VirtualProtect(dest, len, PAGE_EXECUTE_READWRITE, &old_protect);
    memcpy(dest, src, len);
    VirtualProtect(dest, len, old_protect, NULL);
}

void read_bytes(void* src, void* read_buffer, int len){
    protected_read(read_buffer, src, len);
}

void write_bytes(void* src, void* dest, int len){
    protected_read(dest, src, len);
}