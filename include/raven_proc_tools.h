#ifndef RAVEN_PROC_TOOLS_H
#define RAVEN_PROC_TOOLS_H

#include <windows.h>
#include <stdbool.h>
#include <stdint.h>
#include <Psapi.h>
#include <winternl.h>
#include <ks.h>

// PEB REFERENCE: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/peb/index.htm

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

typedef struct {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    PROCESS_BASIC_INFORMATION pbi;
    PPEB peb;
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
 *        and the process will crash. If you wish to send any additional data, make sure the base
 *        of the struct contains a RavenInjectionData struct.
 * 
 * @param dllname  [in]           The name of the dll
 * @param pid      [in]           The process ID
 * @param data     [in, optional] The data sent to the DLL.
 * @param datasize [in, optional] The size of the data sent to the DLL
 * 
 * @return 0 if the code succeeds, otherwise _________
 */
uint8_t inject_dll_ex(const char* dllname, int pid, RavenInjectionData* data, size_t datasize);


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
 * @brief Repairs the entrypoint by writing the original data to it
 * 
 * @param data [in] The entry data for the PE
 */
void repair_entry(EntryData* data);

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
 * @remarks Right now, this function waits for everything to be initialized by sleeping while
 *          EnumProcessModules fails. This is a bit inconsistent. TODO: Make the function know
 *          when all DLLs are loaded and THEN suspend it.
 */
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