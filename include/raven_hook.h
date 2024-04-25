#ifndef RAVEN_HOOK_H
#define RAVEN_HOOK_H

#include <windows.h>
#include "types.h"

#ifdef __GNUC__
#define FUNCTION_RETURN_ADDRESS (__builtin_return_address(0))
#elif defined _MSC_VER
#define FUNCTION_RETURN_ADDRESS (_ReturnAddress())
#endif

/* ----------- HOOK ERROR TABLE ----------- */
#define HOOK_INVALID_TARGET            1
#define HOOK_INVALID_TRAMPOLINE        2
#define HOOK_CANNOT_CREATE_START_RELAY 3
#define HOOK_CANNOT_CREATE_END_RELAY   4

#define MAX_REL_JMP 2147483647

/**
 *        
 * @brief Hooks the specified function in the current process. If the new func is more than
 *        2GB of ram away, a relay function is created, which requires the hook to have a
 *        RAVENRELAY specifier before it.
 * 
 * @param target_func     [in]            The address of the function to hook.
 * @param new_func        [in]            Your new function which will replace the original.
 * @param func_trampoline [out, optional] A pointer which will contain the function trampoline.
 * @param mangled_bytes   [in,  optional] The bytes mangled from the jump instruction.
 * @param original_bytes  [out, optional] The original bytes for unhooking the instruction. This should be at least 5 bytes + the amount of mangled bytes.
 * 
 * @returns 0 If the function succeeds. Otherwise, see the hook error table.
 */
uint8_t hook_function(void* target_func, void* new_func, void** func_trampoline, uint8_t mangled_bytes, uint8_t* original_bytes);




#endif