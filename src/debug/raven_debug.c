#include "raven_debug.h"
#include "raven_memory.h"
#include <stdarg.h>
#include <stdio.h>
#include <windows.h>

void infobox(const char* format, ...){
    char msg[256];
    va_list args;
    va_start(args, format);
    vsprintf_s(msg, 256, format, args);
    va_end(args);
    MessageBox(NULL, msg, "Info", MB_OK);
}

void breakpoint(void* address, uint8_t* original_byte){
    const uint8_t breakpoint = 0xCC;
    protected_write(original_byte, address, 1);
    protected_write(address, &breakpoint, 1);
}