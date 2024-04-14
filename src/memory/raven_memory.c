#include "raven_memory.h"
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

void* get_caller(){
#ifdef _MSC_VER
    return (char*)_ReturnAddress() - 5
#elif defined __GNUC__
    return (char*)__builtin_return_address(0) - 5;
#else
    #pragma message("Warning: get_caller not defined for this compiler!")
#endif
}