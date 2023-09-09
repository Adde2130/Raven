#ifndef RAVEN_BINARY_H
#define RAVEN_BINARY_H

#include <windows.h>
#include <stdint.h>

/**
 * Patches the binary by replacing a piece of code with 
 * a jump operation to the specified function. The minimum
 * size for a jump op is 5 bytes, which is required for
 * this function to work properly.
 * 
 * \param dest           The location for the bytes to be patched
 * \param patch          The address of the new function 
 * \param leftover_bytes The number of remaining bytes from the original instruction
*/
void create_detour(void* dest, void* patch, uint32_t leftover_bytes);

#endif