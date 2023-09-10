#include "raven_memory.h"

#include <stdio.h>
#include "raven_debug.h"

bool hook_function(const char* lib, const char* func_name, void* new_func, void** func_trampoline, uint8_t* original_bytes){
    const size_t jmpsize = 5;
    const uint8_t JMP = 0xE9;

    void* target_func = GetProcAddress(GetModuleHandle(lib), func_name);
    if(!target_func || !pointer_valid(target_func, jmpsize))
        return false;

    if(original_bytes != NULL)
        memcpy(original_bytes, target_func, jmpsize);

    if(func_trampoline != NULL) {
        *func_trampoline = VirtualAlloc(NULL, jmpsize + jmpsize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if(!*func_trampoline)
            return false;

        memcpy(*func_trampoline, target_func, jmpsize);
        uintptr_t trampoline_jmp_target = (uintptr_t)target_func + jmpsize;
        uintptr_t trampoline_jmp_offset = trampoline_jmp_target - ((uintptr_t)*func_trampoline + jmpsize);
        protected_write((uint8_t*)*func_trampoline + jmpsize, &JMP, 1);
        protected_write((uint8_t*)*func_trampoline + jmpsize + 1, &trampoline_jmp_offset, sizeof(uintptr_t) - 1);
    }

    uintptr_t jmp_offset = (uintptr_t)new_func - (uintptr_t)target_func - jmpsize;
    protected_write((uint8_t*)target_func, &JMP, 1);
    protected_write((uint8_t*)target_func + 1, &jmp_offset, jmpsize - 1);

    return true;
}