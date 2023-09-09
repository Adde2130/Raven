#ifndef RAVEN_MEM_H
#define RAVEN_MEM_H

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct {
    DWORD base_address;
    int total_offsets;
    int offsets[];
} mem_ptr;

typedef struct {
    long address;
    uint8_t* patch_bytes;
    uint8_t* original_bytes;
} mem_patch;

/**
 * Uses a memory pointer map to reach the desired address.
 * 
 * Picture the following psuedo-assembly code:
 * 
 * mov ebx, 0x?????        << The address of a class (for example), determined at runtime
 * mov [ebx + 0x10], 0xFF  << The element at offset 16
 * 
 * If we want to access an element from the class at offset 16, we don't know
 * where it is since the address is stored in heap. However, using a pointer map,
 * we can track the location by checking what points to the memory address, and the
 * backtrack it until we find an address in the stack. We can then assume that this
 * location will always point to the currently heap-allocated class. In other words,
 * we can use this static address to find out where the memory allocated on the heap
 * resides.
 * 
 * \param p_mem_ptr The mem_ptr containing the offsets.
 * \returns         The location of the heap memory
*/
void* trace_pointer(mem_ptr* p_mem_ptr);
void  protected_read(void* dest, void* src, int len);
void  read_bytes(void* src, void* read_buffer, int len);
void  write_bytes(void* src, void* dest, int len);

/**
 * @brief Makes sure that the pointer is within the program memory region 
 *        and that it doesn't access protected memory.
 * 
 * @param ptr   The pointer
 * @param size  The size of the pointer
 * @returns true if the pointer is accessing good memory, otherwise false
 */
bool pointer_valid(void* ptr, uint32_t size);

#endif