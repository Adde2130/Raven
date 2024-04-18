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

/**
 * @brief Looks through the current process to find code caves.
 * 
 * @param desired_size [in]           The minimum size required for the code cave
 * @param hModule      [in]           A handle to the module to look for code caves in
 * @param address      [in, optional] If not null, will look at a 2GB offset from
 *                                    the address to ensure 32-bit relative jmp works.
 * 
 * @returns The address of the code cave
 */
void* find_code_cave(const size_t desired_size, const HANDLE hModule, const void* address);

#endif