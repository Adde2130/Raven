#ifndef RAVEN_PROC_TOOLS_H
#define RAVEN_PROC_TOOLS_H

#include "raven_windows_internal.h"
#include "raven_types.h"

#include <stdbool.h>
#include <stdint.h>
#include <Psapi.h>
#include <winternl.h>
#include <ks.h>

typedef struct {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    PROCESS_BASIC_INFORMATION pbi;
    PEB peb;
} RAVEN_PROCESS_INFO;

/**
 * @brief Get the current process PEB
 * 
 * @returns A pointer to the current process PEB
 */
static inline void* GetPEB() {
    return NtCurrentTeb()->ProcessEnvironmentBlock;
}

/**
 * Gets the id of the given process.
 * 
 * \param target [in] The name of the process
 * 
 * \returns      The ID of the process
*/
DWORD get_process_id(const char* target);

/**
 * @brief Repairs the entrypoint of a process by writing the original instructions to the entry.
 * 
 * @param data [in] The entry data for the PE
 */
void repair_entry(EntryData* data);

/**
 * @brief Finds the entry point of an executable by reading the PE headers.
 * 
 * @param executable   [in]  The full path of the executable
 * @param p_entrypoint [out] The address of the entrypoint
 * @return 0 if the code succeeds, otherwise _________
 * 
 * @remarks This requires you to add the module base address when the module is loaded
 *          as this info is not available in the PE.
 */
uint32_t find_entry_point(const char* executable, void** p_entrypoint);
/**
 * @brief Starts a process and creates an infinite jump loop at the entry point, effectively
 *        pausing it but allowing threads to work within the process. Arguments can be passed
 *        as well.
 * 
 * @param executable     [in]            The path to the executable
 * @param argc           [in, optional]  The amount of arguments
 * @param argv           [in, optional]  The arguments
 * @param current_dir    [in, optional]  The directory the executable will be started in
 * @param p_entrypoint   [out]           The address of the entrypoint
 * @param extended_info  [out, optional] Additional info about the process
 * 
 * @return 0 if the code succeeds, otherwise _________
 * 
 * @remarks  This writes a self-jump at the entry point found in the PEB. This will ensure
 			 that all vital modules are loaded before execution. You have to manually resume 
 			 the process by rewriting the original bytes to the entrypoint, which is provided
 			 by the entrydata structure. */
int8_t hijack_entry_point(const char* executable, int argc, const char** argv, const char* current_dir, EntryData* entrydata, RAVEN_PROCESS_INFO* extended_info);

/**
 * @brief Alternate version where you need to create the process in suspended state and
 *        then resume it yourself. This gives you freedom over the process creation.
 * 
 * @param executable     [in]  The path of the executable (needed to find entrypoint)
 * @param hProcess       [in]  Handle to the process
 * @param p_entrypoint   [out] The address of the entrypoint
 * @param original_bytes [out] The original bytes
 */
void hijack_entry_point_ex(const char* executable, HANDLE hProcess, EntryData* entrydata);

/**
 * @brief Get the address of the function within the library
 * 
 * @param lib           The library
 * @param function_name The name of the function
 * @return void* 
 */
void* GetModuleFunction(const char* lib, const char* function_name);

/**
 * @brief Checks if a process is running on WOW64 (32bit process on 64 bit windows).
 * 
 * @param hProcess [in] The process to check
 * @return true if the process is running on wow64, else false
 * 
 * @remarks This is a wrapper for IsWow64Process
 */
bool is_wow64(HANDLE hProcess);

/**
 * @brief Removes the module from the process' loaded modules list without unloading it
 * 
 * @param dllname [in] The base name of the DLL to remove
 * @returns Whether or not the removal succeeded
 */
bool remove_from_loaded_modules(const char* dllname);

/**
 * @brief Returns a handle to the module which the address belongs to
 * 
 * @param address The address to query the module for
 * @return HANDLE 
 */
HANDLE module_from_address(void* address);

#endif
