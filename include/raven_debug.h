#ifndef RAVEN_DEBUG_H
#define RAVEN_DEBUG_H

#include <stdint.h>
#include <windows.h>

#define RAVEN_ERR(msg) __RAVEN_ERR(__FILE__, __LINE__, msg)

void infobox(const char* format, ...);
void writefile(const char* filename, const char* format, ...);

void list_modules(HANDLE hModule);

/**
 * @brief Creates a breakpoint at the specified address. Use the Windows
 *        debugging API to debug the breakpoint.
 * 
 * @param address       The address to insert the breakpoint at
 * @param original_byte An integer pointer which will contain the original byte at the address
*/
void breakpoint(void* address, uint8_t* original_byte);

void printmem(const unsigned char* address, const unsigned int size);

/**
 * @brief WARNING: Interal use only
 */
void __RAVEN_ERR(const char* file, int line, const char* msg);

#endif