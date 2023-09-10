#ifndef RAVEN_HOOK_H
#define RAVEN_HOOK_H

#include <windows.h>
#include "types.h"

/**
 * --- UNFINISHED ---
 *        
 * Hooks the specified function in the current process. The parameters and calling convention
 * needs to match eachother or else the hook will crash the process.  
 * 
 * TODO: add mangled bytes as parameter
 * 
 * @param lib            The name of the library. If NULL, will use the process handle instead. 
 * @param func_to_hook   The name of the function to hook.
 * @param new_func       Your new function which will replace the original
 * @param original_func  A pointer containing the original address of the function.
 * @param original_bytes The original bytes for the instruction. Will be needed if function needs to be unhooked. This is always 5 bytes (size of JMP instruction)
 * 
 * @returns false if the hook failed (and the program didn't crash lol), otherwise true
 */
bool hook_function(const char* lib, const char* func_name, void* new_func, void** original_func, uint8_t* original_bytes);

#endif