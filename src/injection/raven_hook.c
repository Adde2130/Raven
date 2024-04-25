#include <stdio.h>

#include "raven_memory.h"
#include "raven_debug.h"
#include "raven_assembly.h"
#include "raven_hook.h"
#include "raven_binary.h"

void* __create_start_relay(void* start_address, void* destination_address){
    byte_t bytes[] = {
        PUSH_RAX,
        REX8, MOV_EAX, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0's are the address of the hook
        MODRM, 0xE0, // E0 -> E = JMP, 0 = RAX
    };

    void* relay_address = find_unallocated_memory(start_address, sizeof(bytes));
    if(!relay_address)
            return NULL;

    memcpy(bytes + 3, &destination_address, 8);
    memcpy(relay_address, bytes, sizeof(bytes));

    return relay_address;
}

void* __create_end_relay(void* destination_address) {
    byte bytes[] = {
        POP_RAX,
        JMP_REL32, 0x00, 0x00, 0x00, 0x00
    };

    void* relay_address = find_unallocated_memory(destination_address, sizeof(bytes));
    if(!relay_address)
        return NULL;

    int32_t jmp_target = (intptr_t)destination_address - (intptr_t)relay_address - sizeof(bytes);

    memcpy(bytes + 2, &jmp_target, 4);
    memcpy(relay_address, &bytes, sizeof(bytes));

    return relay_address;
}

uint8_t hook_function(void* target_func, void* new_func, void** func_trampoline, uint8_t mangled_bytes, uint8_t* original_bytes) {
    const byte_t JMP_REL32_CONST = JMP_REL32;
    const byte_t NOP_CONST = NOP;

    const size_t jmpsize = 5;
    bool relay = false;

    if(!target_func || !pointer_valid(target_func, jmpsize))
        return HOOK_INVALID_TARGET;

    if(original_bytes != NULL)
        memcpy(original_bytes, target_func, jmpsize + mangled_bytes);

    if(llabs((intptr_t)target_func - (intptr_t)new_func) > MAX_REL_JMP)
        relay = true;

    if(func_trampoline != NULL) {
        *func_trampoline = find_unallocated_memory(target_func, jmpsize + mangled_bytes + jmpsize);
        if(!*func_trampoline)
            return HOOK_INVALID_TRAMPOLINE;
        
        uint64_t trampoline_jmp_target = (intptr_t)target_func - (intptr_t)*func_trampoline - jmpsize;

        DWORD oldprotect;
        memcpy( *func_trampoline, target_func, jmpsize + mangled_bytes); // Overwritten instructions
        memcpy( PTROFFSET(*func_trampoline, jmpsize + mangled_bytes), &JMP_REL32_CONST, 1);
        memcpy( PTROFFSET(*func_trampoline, jmpsize + mangled_bytes + 1), &trampoline_jmp_target, 4); // Write a JMP to the original function
        VirtualProtect(*func_trampoline, jmpsize + jmpsize + mangled_bytes, PAGE_EXECUTE, &oldprotect);
    } 

    if(relay) {
        //TODO: Create relays using code caves if unallocated memory can't be found
        new_func = __create_end_relay(new_func);
        if(!new_func)
            return HOOK_CANNOT_CREATE_END_RELAY;

        new_func = __create_start_relay(target_func, new_func);
        if(!new_func)
            return HOOK_CANNOT_CREATE_START_RELAY;
    }

    intptr_t relative_jmp_offset = (intptr_t)new_func - (intptr_t)target_func - jmpsize;

    protected_write(target_func, &JMP_REL32_CONST, 1); 
    protected_write(PTROFFSET(target_func, 1), &relative_jmp_offset, 4);
    for(int i = 0; i < mangled_bytes; i++)
        protected_write(PTROFFSET(target_func, jmpsize + i), &NOP_CONST, 1);

    return 0;
}