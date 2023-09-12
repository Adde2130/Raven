#include "raven_debug.h"
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

void writefile(const char* filename, const char* format, ...){
    FILE* info = fopen(filename, "a");
    if(info != NULL) {
        char output[256];
        va_list args;
        va_start(args, format);
        vsprintf_s(output, 256, format, args);
        va_end(args); 
        fputs(output, info);
        fclose(info);
    }
}