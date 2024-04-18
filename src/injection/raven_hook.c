#include <stdio.h>

#include "raven_memory.h"
#include "raven_debug.h"
#include "raven_assembly.h"
#include "raven_hook.h"

void* __create_relay(void* start_address, void* destination_address){
    byte_t bytes[] = {
        PUSH_RAX,
        REX8, MOV_EAX, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0's are the address of the hook
        MODRM, 0xE0, // E0 -> E = JMP, 0 = RAX
    };

    void* relay_address = find_unallocated_memory(start_address);

    memcpy(bytes + 3, &destination_address, 8);
    memcpy(relay_address, bytes, sizeof(bytes));

    return relay_address;
}

/**
 * @brief Hooks th
 */
bool hook_function(void* target_func, void* new_func, void** func_trampoline, uint8_t mangled_bytes, uint8_t* original_bytes) {
    const byte_t POP_RAX_CONST = POP_RAX;
    const byte_t NOP_CONST = NOP;
    const byte_t JMP_REL32_CONST = JMP_REL32;

    const size_t jmpsize = 5;
    bool relay = false;

    if(!target_func || !pointer_valid(target_func, jmpsize))
        return false;

    if(original_bytes != NULL)
        memcpy(original_bytes, target_func, jmpsize + mangled_bytes);

    if(llabs((intptr_t)target_func - (intptr_t)new_func) > MAX_REL_JMP)
        relay = true;

    if(func_trampoline != NULL) {
        *func_trampoline = VirtualAlloc(PTROFFSET(target_func, MAX_REL_JMP), jmpsize + mangled_bytes + jmpsize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if(!*func_trampoline)
            return false;
        
        uint64_t trampoline_jmp_target = (intptr_t)target_func - (intptr_t)*func_trampoline - jmpsize;

        DWORD oldprotect;
        memcpy( *func_trampoline, target_func, jmpsize + mangled_bytes); // Overwritten instructions
        memcpy( PTROFFSET(*func_trampoline, jmpsize + mangled_bytes), &JMP_REL32_CONST, 1);
        memcpy( PTROFFSET(*func_trampoline, jmpsize + mangled_bytes + 1), &trampoline_jmp_target, 4); // Write a JMP to the original function
        VirtualProtect(*func_trampoline, jmpsize + jmpsize + mangled_bytes, PAGE_EXECUTE, &oldprotect);
    } 

    if(relay) {
        /* Write POP RAX before the prologue of the hook */
        new_func = PTROFFSET(new_func, -1);
        DWORD oldprotect;
        VirtualProtect(PTROFFSET(new_func, -1), 2, PAGE_EXECUTE_READWRITE, &oldprotect);
        if(!ISGARBAGE(*(unsigned char*)(new_func))) {
            if(*(uint16_t*)PTROFFSET(new_func, -1) == 0x0F0B) {
                protected_write(PTROFFSET(new_func, -1), &NOP_CONST, 1);
            } else {
                clip("%p", new_func);
                infobox("WARNING! REPLACING INSTRUCTION %02X AT 0x%p WHILE TRYING TO HOOK 0x%p\n\nDid you forget to mark a function as a relay?", *(unsigned char*)(new_func), new_func, target_func);
            }
        }

        memcpy(new_func, &POP_RAX_CONST, 1);
        new_func = __create_relay(target_func, new_func);
        VirtualProtect(PTROFFSET(new_func, -1), 2, oldprotect, &oldprotect);

    }

    intptr_t relative_jmp_offset = (intptr_t)new_func - (intptr_t)target_func - jmpsize;

    protected_write(target_func, &JMP_REL32_CONST, 1); 
    protected_write(PTROFFSET(target_func, 1), &relative_jmp_offset, 4);
    clip("%p", target_func);
    infobox("Hooked!");

    return true;
}