#include "raven_assembly.h"
#include "raven_memory.h"
#include "raven_util.h"

#ifdef _WIN64
#include "hde64.h"
#define hde_disasm 	hde64_disasm
#define hde_t		hde64s
#else
#include "hde32.h"
#define hde_disasm 	hde32_disasm
#define hde_t		hde32s
#endif

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

	hde_t hs;
	int parsed_bytes = 0;
	while(parsed_bytes < byte_count) {
		hde_disasm(bytes + parsed_bytes, &hs);

		/* If using relative address, recorrect the offset */
		if(hs.opcode == JMP_REL32 || hs.opcode == CALL) {
			int32_t jmp_offset = hs.imm32;
			int32_t new_offset = get_new_relative_offset(original_address, target_address, jmp_offset);
			memcpy(bytes + parsed_bytes + 1, &new_offset, 4);
		}

		parsed_bytes += hs.len;

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

int raven_shift_stack(int count, int shift_amount, byte_t* asm_out) {
	/*
	 *		generate_stack_shift(4, 2, &asm)
	 *					
	 *					|
	 *					V
	 *
	 *				  BEFORE
	 *
	 *			0019FABC  value5
	 *			0019FAC0  value4
	 *			0019FAC4  value3
	 *			0019FAC8  value2  
	 *			0019FACC  value1
	 *			                      
	 *					|
	 *					V
	 *			                      
	 *			      AFTER
	 *
	 * 			0019FAB4  value5
	 *			0019FAB8  value4
	 *			0019FABC  value3
	 *			0019FAC0  value2
	 *			0019FAC4  value3 <-- They're not removed even
	 *			0019FAC8  value2 <-- though they were shifted
	 *			0019FACC  value1
	 *
	 * 
	 * 	stack_shift:
	 * 		sub		ESP, shift_amount * 4
	 *		push	EAX
	 *		
	 * 		mov	 	EAX, [ESP + 0x4 + shift_amount * 4] <-- start at offset ESP + 0x4 
	 * 		mov  	[ESP + 0x4], REG1						to preserve EAX
	 *		mov	 	EAX, [ESP + 0x8 + shift_amount * 4]  
	 *		mov  	[ESP + 0x8], REG1
	 *		...
	 *		mov	 	EAX, [ESP + (N + 1 + shift_amount) * 4]	
	 *		mov	 	[ESP + (N + 1) * 4], REG1 
	 */
	
	int size = 0;
	if(count == 0 || shift_amount == 0)
		return 0;

	/* sub	ESP, shift_amount * 4 */
	asm_out[size++] = 0x83;
	asm_out[size++] = 0xEC;
	asm_out[size++] = shift_amount * 4;

	asm_out[size++] = PUSH_EAX;

	for(int i = 0; i < count; i++) {
		/* mov  EAX, [ESP + (i + 1 + shift_amount) * 4] */
		asm_out[size++] = 0x8B; 		
		asm_out[size++] = 0x44; 		
		asm_out[size++] = 0x24; 		
		asm_out[size++] = (i + 1 + shift_amount) * 4;

		/* mov  [ESP + (i + 1) * 4], EAX */
		asm_out[size++] = 0x89;		
		asm_out[size++] = 0x44;
		asm_out[size++] = 0x24;
		asm_out[size++] = (i + 1) * 4;
	}

	return size;
}
