#ifndef RAVEN_INJECT_H
#define RAVEN_INJECT_H

#include "raven_types.h"

#include <stdbool.h>
#include <stdint.h>

/* Macro for creating a RavenLoader function for your module injected with
 * `inject_dll_ex`. It is the firs function ran within your injected module.
 * Use it as `RAVENLOADER(void* data) {...}` */
#define RAVENLOADER __declspec(dllexport) DWORD WINAPI RavenLoader

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



#endif
