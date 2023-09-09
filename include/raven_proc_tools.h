#ifndef RAVEN_PROC_TOOLS_H
#define RAVEN_PROC_TOOLS_H

#include <windows.h>
#include <stdbool.h>
#include <stdint.h>
#include <Psapi.h>
#include <winternl.h>
#include <ks.h>

/**
 * Gets the id of the given process.
 * \param target The name of the process
 * \returns      The ID of the process
*/
DWORD get_process_id(const char* target);

/**
 * Inject a dll into the given process. Right now this is a blocking
 * function.
 * 
 * \param dllname The filename of the dll
 * \param pid     The process ID
 * \returns       Whether the injection was successful
*/
bool inject_dll(const char* dllname, int pid);

#endif