#ifndef RAVEN_DETOUR_H
#define RAVEN_DETOUR_H

#define RAVENDETOUR __cdecl

#include <stdint.h>

#define DETOUR_OLD_EAX		(*(uint32_t*)PTROFFSET(esp, -0x04))
#define DETOUR_OLD_ECX		(*(uint32_t*)PTROFFSET(esp, -0x08))
#define DETOUR_OLD_EDX		(*(uint32_t*)PTROFFSET(esp, -0x0C))
#define DETOUR_OLD_EBX		(*(uint32_t*)PTROFFSET(esp, -0x10))
#define DETOUR_OLD_EBP		(*(uint32_t*)PTROFFSET(esp, -0x18))
#define DETOUR_OLD_ESI		(*(uint32_t*)PTROFFSET(esp, -0x1C))
#define DETOUR_OLD_EDI		(*(uint32_t*)PTROFFSET(esp, -0x20))

typedef enum {
	DETOUR_SUCCESS = 0,
	DETOUR_CANNOT_CREATE_TRAMPOLINE = 1,
	DETOUR_CANNOT_CREATE_START_RELAY = 2,
	DETOUR_CANNOT_CREATE_END_RELAY = 3,
} DETOUR_ERROR;


/**
 *        
 * @brief Creates a detour at the target address. The detour function CANNOT have a return value
 * 		  or any parameters, and must use the __stcall (RAVENDETOUR macro) calling convention.
 * 
 * @param target	      [in]            The address to detour.
 * @param detour_func     [in]            The function that will be called.
 * @param mangled_bytes   [in,  optional] The bytes mangled from the jump instruction.
 * @param original_bytes  [out, optional] The original bytes for restoring the function. This should be at least 5 bytes + the amount of mangled bytes.
 * 
 * @returns DETOUR_SUCCESS If the function succeeds. Otherwise, see the detour error enum.
 */
DETOUR_ERROR raven_detour(void* target, void* detour_func, uint8_t mangled_bytes, char** original_bytes);

#endif
