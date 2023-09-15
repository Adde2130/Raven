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

/**
 * @brief Starts a process with the given dll injected
 * 
 * @param executable The path to the executable
 * @param dll        The path to the DLL
 * 
 * @return 0 if the function succeeds. -1 if the process creation failed and
 *         -2 if the dll injection failed.
 */
int8_t start_process_with_injection(const char* executable, const char* dll);

#endif