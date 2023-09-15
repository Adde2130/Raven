#ifndef RAVEN_DEBUG_H
#define RAVEN_DEBUG_H

void infobox(const char* format, ...);
void writefile(const char* filename, const char* format, ...);

/**
 * @brief Creates a breakpoint at the specified address. Use the Windows
 *        debugging API to debug the breakpoint.
 * 
 * @param address       The address to insert the breakpoint at
 * @param original_byte An integer pointer which will contain the original byte at the address
*/
void breakpoint(void* address, uint8_t* original_byte);

#endif