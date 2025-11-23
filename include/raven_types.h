#ifndef RAVEN_TYPES_H
#define RAVEN_TYPES_H

#include <windows.h>

typedef struct {
    HANDLE hModule;
    char* dllname;
} ModuleData;

typedef struct {
    void* entry;
    char bytes[2];
} EntryData;

typedef struct {
    ModuleData mData;
    EntryData eData;
} RavenInjectionData;

typedef enum {
	REG_EAX = (1),
	REG_ECX = (1 << 1),
	REG_EBX = (1 << 2),
	REG_EDX = (1 << 3),
	REG_ESP = (1 << 4),
	REG_EBP = (1 << 5),
	REG_ESI = (1 << 6),
	REG_EDI = (1 << 7)
} RavenRegister;


#endif
