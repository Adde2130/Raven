#ifndef RAVEN_HOOK_H
#define RAVEN_HOOK_H

#include <windows.h>
#include "raven_types.h"
#include "types.h"

#ifdef __GNUC__
#define FUNCTION_RETURN_ADDRESS (__builtin_return_address(0))
#elif defined _MSC_VER
#define FUNCTION_RETURN_ADDRESS (_ReturnAddress())
#endif


/* Macro to define the function pointer type, trampoline, and hook function */
#define RAVEN_CREATE_HOOK(name, address, rettype, callconv, ...)            \
    void* name##_address = (void*) address;                                 \
    typedef rettype (callconv *p##name)(__VA_ARGS__);                       \
    p##name name##_trampoline = NULL;                                       \
    rettype callconv name##_hook(__VA_ARGS__)


/* ----------- HOOK ERROR TABLE ----------- */
#define HOOK_INVALID_TARGET            1
#define HOOK_CANNOT_CREATE_TRAMPOLINE  2
#define HOOK_CANNOT_CREATE_START_RELAY 3
#define HOOK_CANNOT_CREATE_END_RELAY   4
/* ---------------------------------------- */

typedef struct {
	void* target;
	void* hook;
	void** p_trampoline;
	int stack_parameters;
	RavenRegister register_parameters;
	RavenRegister return_register;
} RavenHookSettings;

/**
 *        
 * @brief Hooks the specified function in the current process. If the new func is more than
 *        2GB of ram away, a relay function is created.
 * 
 * @param target_func     [in]            The address of the function to hook.
 * @param hook_func       [in]            Your new function which will replace the original.
 * @param func_trampoline [out, optional] A pointer which will contain the function trampoline.
 * @param mangled_bytes   [in,  optional] The bytes mangled from the jump instruction.
 * @param original_bytes  [out, optional] The original bytes for unhooking the instruction. This should be at least 5 bytes + the amount of mangled bytes.
 * 
 * @returns 0 If the function succeeds. Otherwise, see the hook error table.
 */
uint8_t raven_hook(void* target, void* hook, void** trampoline);

uint8_t raven_hook_ex(RavenHookSettings* settings);


#endif
