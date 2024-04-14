#ifndef RAVEN_HOOK_H
#define RAVEN_HOOK_H

#include <windows.h>
#include "types.h"

/**
 *        
 * Hooks the specified function in the current process. The parameters and calling convention
 * needs to match eachother or else the hook will crash the process.  
 * 
 * @param target_func     [in]            The address of the function to hook.
 * @param new_func        [in]            Your new function which will replace the original
 * @param func_trampoline [out, optional] A pointer which will contain the function trampoline.
 * @param mangled_bytes   [in,  optional] The bytes mangled from the jump instruction.
 * @param original_bytes  [out, optional] The original bytes for the instruction. Will be needed if function needs to be unhooked. This is always 5 bytes (size of JMP instruction)
 * 
 * @returns false if the hook failed (and the program didn't crash lol), otherwise true
 */
bool hook_function(void* target_func, void* new_func, void** func_trampoline, uint8_t mangled_bytes, uint8_t* original_bytes);

#endif