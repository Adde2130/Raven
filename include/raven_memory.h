#ifndef RAVEN_MEM_H
#define RAVEN_MEM_H

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Macro for getting the byte offset from a pointer
 * 
 * @param ptr    The address, expressed as a pointer or an integer
 * @param offset The offset from the address
 */
#define PTROFFSET(ptr, offset) ((void*)(((uintptr_t)(ptr)) + ((intptr_t)(offset))))

#define MEMORY_BLOCK_SIZE 0x1000
#define MAX_MEMORY_RANGE 0x40000000

typedef struct {
    void* base_address;
    int total_offsets;
    int offsets[];
} mem_ptr;

typedef struct {
    void* address;
    uint8_t* patch_bytes;
    uint8_t* original_bytes;
    size_t size;
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
 * @param p_mem_ptr [in]  The mem_ptr containing the offsets
 * @param ptr       [out] The final address 
 * 
 * @returns          0, if the function succeeds.
 *                   1, if one of the offsets are null pointers.
 *                   2, if one of the offsets point to invalid memory.
*/
uint8_t trace_pointer(const mem_ptr* p_mem_ptr, void** ptr);

/**
 * @brief Writes to memory in a safe way by temporarily removing the memory protection
 *        and then restoring it after the operation.
 * 
 * @param dest Pointer to where the bytes should be written
 * @param src  Pointer to where to read the bytes from
 * @param len  The amount of bytes to read
 */
void  protected_write(void* dest, const void* src, int len);

/**
 * @brief Fills the destination with the byte specified
 * 
 * @param dest [in] The destination
 * @param byte [in] The byte
 * @param len  [in] The number of bytes to fill in
 */
void  protected_fill_bytes(void* dest, const char byte, int len);

void  read_bytes(void* src, void* read_buffer, int len);
void  write_bytes(void* src, void* dest, int len);

/**
 * @brief Writes the patch to memory of the executable
 * 
 * @param patch [in] The patch
 */
void patch(mem_patch* patch);

/**
 * @brief Makes sure that the pointer is within the program memory region 
 *        and that it doesn't access protected memory.
 * 
 * @param ptr   The pointer
 * @param size  The size of the pointer
 * 
 * @returns true if the pointer is accessing good memory, otherwise false
 */
bool pointer_valid(void* ptr, uint32_t size);

/**
 * @brief Finds a memory region in proximity to the base with unallocated memory
 * 
 * @param base         [in] The base address
 * @param desired_size [in] The desired size of the memory region
 * @param range        [in] The range 
 * 
 * @returns The address of the unallocated memory 
 */
void* find_unallocated_memory(void* base);

#endif