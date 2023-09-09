#include "raven_memory.h"

uintptr_t* trace_pointer(mem_ptr* p_mem_ptr){
    uintptr_t* location = (uintptr_t*)((uintptr_t)GetModuleHandle(NULL) + (uintptr_t)p_mem_ptr->base_address);
    for(int i = 0; i < p_mem_ptr->total_offsets; i++) {
        if(location == NULL)
            return NULL;

        location = (uintptr_t*)(*location + p_mem_ptr->offsets[i]);
    }
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