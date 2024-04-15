#include "raven_debug.h"
#include "raven_memory.h"
#include <stdarg.h>
#include <stdio.h>
#include <windows.h>
#include <psapi.h>

void infobox(const char* format, ...){
    char msg[512];
    va_list args;
    va_start(args, format);
    vsprintf_s(msg, 512, format, args);
    va_end(args);
    MessageBox(NULL, msg, "Info", MB_OK);
}

void list_modules(HANDLE hProcess){
    HMODULE hModules[1024];
    DWORD bytesneeded;
    EnumProcessModules(hProcess, hModules, sizeof(hModules), &bytesneeded);

    char msg[2048] = "MODULES:\n";
    for(uint32_t i = 0; i < bytesneeded / sizeof(HMODULE); i++){
        char filename[MAX_PATH];
        GetModuleFileNameA(hModules[i], filename, MAX_PATH);
        sprintf(msg + strlen(msg), "%s\n", filename);
    }

    MessageBoxA(NULL, msg, "MODULES", MB_OK);
}

void breakpoint(void* address, uint8_t* original_byte){
    const uint8_t breakpoint = 0xCC;
    protected_write(original_byte, address, 1);
    protected_write(address, &breakpoint, 1);
}

void writefile(const char* filename, const char* format, ...){
    FILE* info = fopen(filename, "a");
    if(info != NULL) {
        char output[1024];
        va_list args;
        va_start(args, format);
        vsprintf_s(output, 1024, format, args);
        va_end(args); 
        fputs(output, info);
        fclose(info);
    }
}

void printmem(const unsigned char* address, const unsigned int size){
#ifndef _WIN64
    const char offset = 4;
#else
    const char offset = 8;
#endif
    printf("0x00 | ");
    for(unsigned int i = 0; i < size; i++) {
        printf("%02X ", address[i]);
        if(!((i + 1) % offset) && i != size - 1)
            printf("\n0x%02X | ", i+1);
    }
    printf("\n");
}

/**
 * @brief ChatGPT ahh code
 * 
 * @param hProc The process of which to iterate over the modules of
 */
void iterate_modules(HANDLE hProc){
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded)) {
        for (long long unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            TCHAR szModName[MAX_PATH];
            if (GetModuleFileNameEx(hProc, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
                printf("Module %lld: %s\n", i + 1, szModName);

                MODULEINFO moduleInfo;
                if (GetModuleInformation(hProc, hMods[i], &moduleInfo, sizeof(moduleInfo))) {
                    printf("   Base Address: 0x%p\n", moduleInfo.lpBaseOfDll);
                    printf("   Size: %ld bytes\n", moduleInfo.SizeOfImage);
                } else {
                    printf("   Failed to get module information. Error code: %ld\n", GetLastError());
                }
            }
        }
    } else {
        printf("Failed to enumerate process modules. Error code: %ld\n", GetLastError());
    }
}

void __RAVEN_ERR(const char* file, int line, const char* msg){
    printf(
        "\n\e[0;31m------------------------------------------------------------------------------------\n"
        "RAVEN_ERR raised at line %d in file '%s':\n"
        "%s\n"
        "------------------------------------------------------------------------------------\e[0;37m\n\n"
        , line, file, msg
    );
    exit(1);
}