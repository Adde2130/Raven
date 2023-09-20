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
 * 
 * \param target [in] The name of the process
 * 
 * \returns      The ID of the process
*/
DWORD get_process_id(const char* target);

/**
 * Inject a dll into the given process. Right now this is a blocking
 * function.
 * 
 * \param dllname [in] The filename of the dll
 * \param pid     [in] The process ID
 * 
 * \returns       Whether the injection was successful
*/
bool inject_dll(const char* dllname, int pid);

/**
 * @brief A more complex version of inject_dll. This injects the DLL with the given data
 *        and requires the DLL to have a DWORD WINAPI RavenLoader(LPVOID) function to call instead in order
 *        to handle the data and create the main thread. If the main thread is created
 *        in PROCESS_ATTACH under DllMain, then the thread will be created in the injector
 *        and the process will crash.
 * 
 * @param dllname  [in] The name of the dll
 * @param pid      [in] The process ID
 * @param data     [in] The data sent to the DLL
 * @param datasize [in] The size of the data sent to the DLL
 * 
 * @return 0 if the code succeeds, otherwise _________
 */
uint8_t inject_dll_ex(const char* dllname, int pid, void* data, size_t datasize);

/**
 * @brief Starts a process and creates an infinite jump loop at the entry point, effectively
 *        pausing it but allowing threads to work within the process. 
 * 
 * @param executable     [in]  The path to the executable
 * @param p_entrypoint   [out] The address of the entrypoint
 * @param original_bytes [out] The 2 bytes originally at the entry point
 * 
 * @return 0 if the code succeeds, otherwise _________
 * 
 * @remarks Right now, this function waits for everything to be initialized by sleeping while
 *          EnumProcessModules fails. This is a bit inconsistent. TODO: Make the function know
 *          when all DLLs are loaded and THEN suspend it.
 */
int8_t hijack_entry_point(const char* executable, uintptr_t* p_entrypoint, char* original_bytes);

/**
 * @brief Starts a process and creates an infinite jump loop at the user specified address, supposed to
 *        be the entry point.
 * 
 * @param executable [in] The executable file
 * @param main       [in] The address of the entry point
 * 
 * @return 0 of the code succeeeds, otherwise _________
 */
int8_t hijack_entry_point_alternate(const char* executable, uintptr_t* p_entrypoint, char* original_bytes);

/**
 * @brief Checks if a process is running on WOW64 (32bit process on 64 bit windows).
 * 
 * @param hProcess [in] The process to check
 * @return true if the process is running on wow64, else false
 * 
 * @remarks This is a wrapper for IsWow64Process
 */
bool is_wow64(HANDLE hProcess);

#endif