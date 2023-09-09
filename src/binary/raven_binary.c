#include "raven_binary.h"
#include "raven_memory.h"

void create_detour(void* dest, void* patch, uint32_t leftover_bytes){
    const int jmp_length = 5; // JMP instruction bytes
    int patch_length = jmp_length + leftover_bytes;
    uintptr_t offset = ((uintptr_t)patch - (uintptr_t)dest) - jmp_length;
    byte* patch_bytes = malloc(sizeof(byte) * patch_length);
    memset(patch_bytes, 0x90, patch_length); // NO-OP
    patch_bytes[0] = 0xe8;
    memcpy(patch_bytes + 1, &offset, jmp_length - 1);
    write_bytes(dest, patch_bytes, patch_length);
}