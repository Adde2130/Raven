#ifndef RAVEN_UTIL_H
#define RAVEN_UTIL_H

#include "Raven.h"

/**
 * @brief Turns a wide string into a normal c string. The new string is allocated on the heap with malloc,
 *        and needs to be freed after use.
 * 
 * @param str    The wide string to convert
 * @returns      A pointer to the new c string
 */
char* wstr_to_str(LPCWSTR str);

/**
 * @brief Removes the list entry from the linked list it belongs to
 * 
 * @param list             [in] The entry to remove
 * @param protected_memory [in] Whether or not the memory region has protection
 */
void patch_linked_list(LIST_ENTRY* list, bool protected_memory);

#endif