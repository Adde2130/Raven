#include "raven_memory.h"

#include <stdio.h>
#include "raven_debug.h"

/**
 * @brief Hook for 32-bit Windows applications. Writes a 5 byte relative jmp to the beginning of the function. 
 * 
 */
bool __hook_function_32(void* target_func, void* new_func, void** func_trampoline, uint8_t mangled_bytes, uint8_t* original_bytes){
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

/**
 * @brief Hook for 64-bit Windows applications. Uses 14 bytes to load the absolute address into RAX
 *        and then jumps using the RAX register. Assumes that there is empty space before the hook
 *        and adds a POP RAX before the prologue. Looking for an alternative method of doing this.
 */
bool __hook_function_64(void* target_func, void* new_func, void** func_trampoline, uint8_t mangled_bytes, uint8_t* original_bytes) {
    const uint8_t PUSH_RAX  = { 0x50 };
    const uint8_t MOV_RAX[] = { 0x48, 0xB8 };
    const uint8_t JMP_RAX[] = { 0xFF, 0xE0 };
    const uint8_t POP_RAX   = { 0x58 };
    const uint8_t NOP       = { 0x90 };

    uint8_t bytes_to_write[] = {
        PUSH_RAX,
        MOV_RAX[0], MOV_RAX[1], 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0's are the address of the hook
        JMP_RAX[0], JMP_RAX[1],
        POP_RAX  // <---- We jump to this instruction
    };

    const size_t jmpsize = sizeof(bytes_to_write);

    if(!target_func || !pointer_valid(target_func, jmpsize))
        return false;

    if(original_bytes != NULL)
        memcpy(original_bytes, target_func, jmpsize + mangled_bytes);

    if(func_trampoline != NULL) {
        *func_trampoline = VirtualAlloc(NULL, jmpsize + mangled_bytes + jmpsize - 1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if(!*func_trampoline)
            return false;
        
        uint64_t trampoline_jmp_target = (uintptr_t)target_func + jmpsize - 1; // Remember, we want to jump to the POP RAX instruction

        DWORD oldprotect;
        memcpy( (uint8_t*)(*func_trampoline), target_func, jmpsize + mangled_bytes); // Overwritten instructions
        memcpy(bytes_to_write + sizeof(PUSH_RAX) + sizeof(MOV_RAX), &trampoline_jmp_target, 8); 
        memcpy( (uint8_t*)(*func_trampoline) + jmpsize + mangled_bytes, bytes_to_write, jmpsize - 1); // Write a JMP to the original function
        VirtualProtect(*func_trampoline, jmpsize + jmpsize + mangled_bytes, PAGE_EXECUTE, &oldprotect);
    } 

    /* Write POP RAX before the prologue of the hook. Will replace code if too tightly packed :/ */
    uintptr_t destination = (uintptr_t) new_func - 1;
    DWORD oldprotect;
    VirtualProtect((void*) destination, 1, PAGE_EXECUTE_READWRITE, &oldprotect);
    if(*(unsigned char*)(destination) != 0x90)
        infobox("WARNING! REPLACING INSTRUCTION %02X AT 0x%p WHILE TRYING TO HOOK 0x%p", *(unsigned char*)(destination), (void*)destination, target_func);
    memcpy((void*)destination, &POP_RAX, 1);
    VirtualProtect((void*) destination, 1, PAGE_EXECUTE, &oldprotect);

    protected_write(bytes_to_write + sizeof(PUSH_RAX) + sizeof(MOV_RAX), &destination, 8);
    protected_write(target_func, bytes_to_write, jmpsize);
    for(int i = 0; i < mangled_bytes; i++)
        protected_write( (uint8_t*)target_func + jmpsize + i, &NOP, 1);

    return true;
}