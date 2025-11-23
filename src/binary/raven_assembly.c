#include "raven_assembly.h"
#include "raven_memory.h"

static const int JMP_SIZE = 5;

static int32_t get_new_relative_offset(void* original_address, void* new_address, int32_t offset) {
	void* jmp_address = PTROFFSET(original_address, 5);
	void* function_address = PTROFFSET(jmp_address, offset);

	int32_t new_offset = (intptr_t)function_address - (intptr_t)new_address - JMP_SIZE;

	return new_offset;
}

void resolve_mangled_bytes(void* original_address, void* target_address, uint8_t byte_count, byte_t* mangled_bytes) {
	byte_t bytes[byte_count];

	protected_write(bytes, original_address, byte_count);

	/* If using relative address, recorrect the offset */
	if(bytes[0] == JMP_REL32 || bytes[0] == CALL) {
		int32_t jmp_offset = *(int32_t*)(bytes + 1);

		int32_t new_offset = get_new_relative_offset(original_address, target_address, jmp_offset);
		
		memcpy(bytes + 1, &new_offset, 4);

	}

	memcpy(mangled_bytes, bytes, byte_count);

}

/* TODO: Place this with `raven_nop` in a file called raven_instructions.c or similar */
uint8_t raven_jmp(void* from, void* to) {
	byte_t instruction[] = {
		JMP_REL32,
		0x00, 0x00, 0x00, 0x00
	};

	if(llabs( (intptr_t)from - (intptr_t)to ) > MAX_REL_JMP)
		return 1;

	int32_t offset = (intptr_t)to - (intptr_t)from - 5;

	memcpy(instruction + 1, &offset, 4);

	protected_write(from, instruction, 5);
	return 0;
}
