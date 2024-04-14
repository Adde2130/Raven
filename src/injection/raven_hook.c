#include "raven_memory.h"

#include <stdio.h>
#include "raven_debug.h"

bool hook_function(void* target_func, void* new_func, void** func_trampoline, uint8_t mangled_bytes, uint8_t* original_bytes){
    const size_t jmpsize = 5;
    const uint8_t JMP = 0xE9;

    if(!target_func || !pointer_valid(target_func, jmpsize))
        return false;

    if(original_bytes != NULL)
        memcpy(original_bytes, target_func, jmpsize + mangled_bytes);

    if(func_trampoline != NULL) {
        *func_trampoline = VirtualAlloc(NULL, jmpsize + jmpsize + mangled_bytes, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if(!*func_trampoline)
            return false;

        intptr_t trampoline_jmp_target = (intptr_t)target_func + jmpsize;
        intptr_t trampoline_jmp_offset = trampoline_jmp_target - ((intptr_t)*func_trampoline + jmpsize + jmpsize);

        DWORD oldprotect;
        memcpy(*func_trampoline, target_func, jmpsize + mangled_bytes);
        memcpy( (uint8_t*)(*func_trampoline) + jmpsize + mangled_bytes, &JMP, 1);
        memcpy( (uint8_t*)(*func_trampoline) + jmpsize + mangled_bytes + 1, &trampoline_jmp_offset, jmpsize - 1);
        VirtualProtect(*func_trampoline, jmpsize + jmpsize + mangled_bytes, PAGE_EXECUTE, &oldprotect);
    } 

    intptr_t jmp_offset = (intptr_t)new_func - (intptr_t)target_func - jmpsize;
    protected_write((uint8_t*)target_func, &JMP, 1);
    protected_write((uint8_t*)target_func + 1, &jmp_offset, jmpsize - 1);

    return true;
}