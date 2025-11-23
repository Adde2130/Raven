#include <stdio.h>

#include "raven_memory.h"
#include "raven_debug.h"
#include "raven_assembly.h"
#include "raven_hook.h"
#include "raven_binary.h"


#ifdef _WIN64
#include "hde64.h"
#define hde_disasm 	hde64_disasm
#define hde_t		hde64s
#else
#include "hde32.h"
#define hde_disasm 	hde32_disasm
#define hde_t		hde32s
#endif


static void* __create_start_relay(void* start_address, void* destination_address){
    byte_t bytes[] = {
        PUSH_RAX,
        REX8, MOV_EAX, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0's are the address of the hook
        MODRM, 0xE0, // E0 -> E = JMP, 0 = RAX
    };

    void* relay_address = find_unallocated_memory(start_address, sizeof(bytes));
    if(!relay_address)
            return NULL;

    memcpy(bytes + 3, &destination_address, 8);
    memcpy(relay_address, bytes, sizeof(bytes));

    return relay_address;
}

static void* __create_end_relay(void* destination_address) {
    byte bytes[] = {
        POP_RAX,
        JMP_REL32, 0x00, 0x00, 0x00, 0x00
    };

    void* relay_address = find_unallocated_memory(destination_address, sizeof(bytes));
    if(!relay_address)
        return NULL;

    int32_t jmp_target = (intptr_t)destination_address - (intptr_t)relay_address - sizeof(bytes);

    memcpy(bytes + 2, &jmp_target, 4);
    memcpy(relay_address, &bytes, sizeof(bytes));

    return relay_address;
}

static uint8_t __create_func_trampoline(void** trampoline, void* target_func, uint8_t mangled_bytes) {
	const byte_t JMP_REL32_CONST = JMP_REL32;
    const size_t jmpsize = 5;

	*trampoline = find_unallocated_memory(target_func, jmpsize + mangled_bytes + jmpsize);
	if(!*trampoline)
		return HOOK_CANNOT_CREATE_TRAMPOLINE;
	
	uint64_t trampoline_jmp_target = (intptr_t)target_func - (intptr_t)*trampoline - jmpsize;


	byte_t bytes[jmpsize + mangled_bytes];
	resolve_mangled_bytes(target_func, *trampoline, jmpsize + mangled_bytes, bytes);
	memcpy( *trampoline, bytes, jmpsize + mangled_bytes); // Overwritten instructions
																
	memcpy( PTROFFSET(*trampoline, jmpsize + mangled_bytes), &JMP_REL32_CONST, 1);
	memcpy( PTROFFSET(*trampoline, jmpsize + mangled_bytes + 1), &trampoline_jmp_target, 4); // Write a JMP to the original function

	DWORD oldprotect;
	VirtualProtect(*trampoline, jmpsize + jmpsize + mangled_bytes, PAGE_EXECUTE, &oldprotect);

	return 0;
}

uint8_t __get_mangled_bytes(void* target) {
	int instruction_size = 0;
	hde_t hs;
	while(instruction_size < 5)
		instruction_size += hde_disasm(PTROFFSET(target, instruction_size), &hs);

	return instruction_size - 5;
}

uint8_t raven_hook(void* target, void* hook, void** trampoline) {
    const size_t jmpsize = 5;
    bool relay = false;

	uint8_t mangled_bytes = __get_mangled_bytes(target);

    if(!target || !pointer_valid(target, jmpsize))
        return HOOK_INVALID_TARGET;

    if(llabs((intptr_t)target - (intptr_t)hook) > MAX_REL_JMP)
        relay = true;

    if(trampoline != NULL) {
		uint8_t error = __create_func_trampoline(trampoline, target, mangled_bytes);
		if(error)
			return error;
    } 

    if(relay) {
        //TODO: Create relays using code caves if unallocated memory can't be found
        hook = __create_end_relay(hook);
        if(!hook)
            return HOOK_CANNOT_CREATE_END_RELAY;

        hook = __create_start_relay(target, hook);
        if(!hook)
            return HOOK_CANNOT_CREATE_START_RELAY;
    }

	raven_jmp(target, hook);
	raven_nop(PTROFFSET(target, jmpsize), mangled_bytes);

    return 0;
}

static int __get_highest_bit(uint8_t num) {
	int bit = 0;
	while(num > 0) {
		bit++;
		num>>=1;
	}
	return bit;
}

static int __get_bit_count(uint8_t num) {
	int bits = 0;
	while(num > 0) {
		if(num & 1)
			bits++;
		num>>=1;
	}
	return bits;
}

static void* __create_start_relay_ex32(void* start_address, void* destination_address){
    void* relay_address = find_unallocated_memory(start_address, 6);
    if(!relay_address)
            return NULL;

	raven_write8(relay_address, PUSH_EAX);
	raven_jmp(relay_address + 1, destination_address);

    return relay_address;
}

/* TODO: DO NOT PUSHAD, INSTEAD PUSH ALL EXCEPT EAX IN THE EVENT OF A RETURN VALUE */
static void* __create_end_relay_ex32(void* destination, uint8_t stack_parameters, RavenRegister register_parameters) {
	/**
	 * Create the following relay:
	 *		
	 *	end_relay_32:
	 *		pop 	EAX
     *
	 * 		
	 *		pushad
     *
	 *		mov		ECX, ESP
	 *		add		ECX, 0x20
     *
	 * 	# for each stack parameter
	 *		push 	[ECX + N * 4]
	 *		push	[ECX + (N - 1) * 4]
	 *		push	[ECX + (N - 2) * 4]
	 *		...
	 *
	 * 	# for each register parameter
	 *		push	EDX
	 *		push	ECX <-- SPECIAL CASE:
	 *				 |
	 *				 v
	 *		push 	[ECX - 0x8] <-- location of ECX after pushad
     *
	 *		call 	hook
     *
	 * 	# Since we want to pop all values EXCEPT EAX in case of a return value, we
	 * 	# do a manual popad 
	 * 		pop		EDI 
	 * 		pop		ESI
	 * 		pop		EBP
	 *		add		ESP, 4
	 *		pop		EBX
	 *		pop		EDX
	 *		pop		ECX
     *		add		ESP, 4 <-- pop EAX would be here
	 * 		
	 *		ret <-- since it is a stdcall, we do 0xC2 + STACK_SIZE
	 *	
	 */

	byte_t bytes[256] = { 0 };
	int byte_index = 0;

	byte_t prologue[] = {
		POP_EAX,
		PUSHAD,
		0x89, 0xe1, 			// mov ECX, ESP
		0x83, 0xc1, 0x20		// add ECX, 0x20
	};

	memcpy(bytes, prologue, sizeof(prologue));
	byte_index += sizeof(prologue);


	byte_t stack_parameter_pushing[256] = {0};
	int	stack_parameter_pushing_len = stack_parameters * 3;	
	for(int i = 0; i < stack_parameters; i++) {
		/* push [ECX + (stack_parameters - i) * 4] */
		stack_parameter_pushing[i * 3 + 0] = 0xFF;
		stack_parameter_pushing[i * 3 + 1] = 0x71;
		stack_parameter_pushing[i * 3 + 2] = (stack_parameters - i) * 4;
	}

	memcpy(bytes + byte_index, stack_parameter_pushing, stack_parameter_pushing_len);
	byte_index += stack_parameter_pushing_len;


	byte register_parameter_pushing[256] = {0};
	int register_parameter_pushing_len = 0;
	int highest_register_bit;
	for(int i = 0; register_parameters;) {
		highest_register_bit = __get_highest_bit(register_parameters);
		RavenRegister current_register = 1 << (highest_register_bit - 1);

		if(current_register == REG_ECX) {
			/* push [ECX - 0x8] */
			register_parameter_pushing[i++] = 0xFF;
			register_parameter_pushing[i++] = 0x71;
			register_parameter_pushing[i++] = 0xF8;
			register_parameter_pushing_len += 3;
		} else if(current_register) {
			/* push REG */
			register_parameter_pushing[i++] = 0x50 + highest_register_bit - 1;
			register_parameter_pushing_len++;
		}

		register_parameters &= ~current_register;
		
	}

	memcpy(bytes + byte_index, register_parameter_pushing, register_parameter_pushing_len);
	byte_index += register_parameter_pushing_len;


	void* relay_address = find_unallocated_memory(destination, byte_index + 7);
	if(!relay_address)
		return NULL;

	/* call destination */
	void* jmp_address = PTROFFSET(relay_address, byte_index + 5);
	int32_t offset = (intptr_t)destination - (intptr_t)jmp_address;
	
	byte_t function_call[] = {
		CALL,
		0x00, 0x00, 0x00, 0x00
	};
	memcpy(function_call + 1, &offset, 4);

	memcpy(bytes + byte_index, function_call, sizeof(function_call));
	byte_index += sizeof(function_call);

	/* popad -> ret */
	byte_t epilogue[] = {
		POP_EDI,
		POP_ESI,
		POP_EBP,
		0x83, 0xC4, 0x04, // add ESP, 4
		POP_EBX,
		POP_EDX,
		POP_ECX,
		0x83, 0xC4, 0x04, // overwrite EAX
						  
		RET_N, 0x00, 0x00
	};

	uint16_t stack_size = stack_parameters * 4;
	memcpy(epilogue + sizeof(epilogue) - 2, &stack_size, 2);

	memcpy(bytes + byte_index, epilogue, sizeof(epilogue));
	byte_index += sizeof(epilogue);


	protected_write(relay_address, bytes, byte_index);
	return relay_address;
}

static uint8_t __create_func_trampoline_ex32(void** trampoline, void* target_func, uint8_t mangled_bytes, RavenRegister register_parameters) {
	/**
	 * 		First thing on the stack is the return address, we need it to fuck off.
	 * 		Move the variables needed for the registers up and then put the return
	 * 		address below. E.g:
	 *
	 *		0019FABC  ret_address
	 *		0019FAC0  reg2
	 *		0020FAC4  reg1
	 *		0019FAC8  stack1  
	 *		0019FACC  stack2
	 *
	 *				|
	 *				V
	 *
	 *		0019FABC  reg2
	 *      0019FAC0  reg1
	 *      0020FAC4  ret_address
	 *      0019FAC8  stack1
	 *      0019FACC  stack2
	 *
	 * 
	 *	trampoline:
	 * 		sub	 ESP, 4
	 * 		mov	 REG1, [ESP + 4]
	 * 		mov  [ESP], REG1
	 *		mov  REG1, [ESP + 8]
	 *		mov  [ESP + 4], REG1
	 *		...
	 *		mov  REG1, [ESP + (N + 1) * 4]
	 *		mov	 [ESP + N * 4], REG1
	 *
	 *		mov  REG1, [ESP] <-- ret address
	 *		mov  [ESP + (N + 1) * 4], REG1
	 *
	 *		add	 ESP, 4
	 *
	 *		pop	 REG1 <-- for each register EAX -> EDI used
     *		pop	 REG2 <-- 
	 *		...
	 *		pop  REGN
	 *
	 *		overwritten_instruction
	 *
	 *		jmp target_func
	 *	
	 */

	const int jmp_size = 5;
	byte_t bytes[256] = { 0 }; 
	int overwritten_instruction_len = mangled_bytes + jmp_size;


	byte_t stack_flipper[64];
	size_t stack_flipper_size = 0;

	/* sub ESP, 4 */
	stack_flipper[0] = 0x83;
	stack_flipper[1] = 0xEC;
	stack_flipper[2] = 0x04;
	stack_flipper_size += 3;

	RavenRegister current_register_byte = 0x44 | ((__get_highest_bit(register_parameters) - 1) << 3);
	int register_parameter_count = __get_bit_count(register_parameters);
	for(int i = 0; i <= register_parameter_count; i++) {
		/* mov REG1, [ESP + (i + 1) * 4] */
		stack_flipper[stack_flipper_size++] = 0x8B;
		stack_flipper[stack_flipper_size++] = current_register_byte;
		stack_flipper[stack_flipper_size++] = 0x24;
		stack_flipper[stack_flipper_size++] = (i + 1) * 4;

		/* mov [ESP + i * 4], REG1 */
		stack_flipper[stack_flipper_size++] = 0x89;
		stack_flipper[stack_flipper_size++] = current_register_byte;
		stack_flipper[stack_flipper_size++] = 0x24;
		stack_flipper[stack_flipper_size++] = i * 4;
	}

	/* mov REG1, [ESP] */ 
	stack_flipper[stack_flipper_size++] = 0x8B;
	stack_flipper[stack_flipper_size++] = current_register_byte;
	stack_flipper[stack_flipper_size++] = 0x24;
	stack_flipper[stack_flipper_size++] = 0x0;

	/* mov [ESP + (register_parameter_count + 1) * 4], REG1 */
	stack_flipper[stack_flipper_size++] = 0x89;
	stack_flipper[stack_flipper_size++] = current_register_byte;
	stack_flipper[stack_flipper_size++] = 0x24;
	stack_flipper[stack_flipper_size++] = (register_parameter_count + 1) * 4;


	stack_flipper[stack_flipper_size++] = 0x83;
	stack_flipper[stack_flipper_size++] = 0xC4;
	stack_flipper[stack_flipper_size++] = 0x04;
	memcpy(bytes, stack_flipper, stack_flipper_size);


	size_t prologue_size = stack_flipper_size;
	for(int i = 0; register_parameters; i++) {
		if(register_parameters & 1)
			bytes[prologue_size++] = 0x58 + i; // pop REGi

		register_parameters >>= 1;
	}

	int trampoline_size = prologue_size + overwritten_instruction_len + jmp_size;
	*trampoline = find_unallocated_memory(target_func, trampoline_size);
	if(*trampoline == NULL)
		return HOOK_CANNOT_CREATE_TRAMPOLINE;

	/* overwritten instruction */
	protected_write(bytes + prologue_size, target_func, overwritten_instruction_len);


	byte_t jmp_instruction[] = {
		JMP_REL32,
		0x00, 0x00, 0x00, 0x00
	};

	void* jmp_address = *trampoline + trampoline_size;
	int32_t offset = (intptr_t)target_func + jmp_size - (intptr_t)jmp_address;

	memcpy(jmp_instruction + 1, &offset, 4);
	memcpy(bytes + prologue_size + overwritten_instruction_len, jmp_instruction, jmp_size);

	protected_write(*trampoline, bytes, trampoline_size);
	return 0;
}

uint8_t raven_hook_ex(void* target_func, void* hook_func, void** func_trampoline, uint8_t param_count, RavenRegister parameter_registers, uint8_t mangled_bytes, uint8_t* original_bytes) {
	int jmp_size = 5;

	if(parameter_registers == 0) {
		raven_hook(target_func, hook_func, func_trampoline);
	}

	int register_count = __get_bit_count(parameter_registers);
	int stack_parameter_count = param_count - register_count;

    if(!target_func || !pointer_valid(target_func, jmp_size))
        return HOOK_INVALID_TARGET;

    if(original_bytes != NULL)
        protected_write(original_bytes, target_func, jmp_size + mangled_bytes);


    if(func_trampoline != NULL) {
		uint8_t error = __create_func_trampoline_ex32(
			func_trampoline, target_func,
			mangled_bytes, parameter_registers
		);

		if(error)
			return error;
    } 

	void* end_relay = __create_end_relay_ex32(hook_func, stack_parameter_count, parameter_registers);
	if(!end_relay)
		return HOOK_CANNOT_CREATE_END_RELAY;

	void* start_relay = __create_start_relay_ex32(target_func, end_relay);
	if(!start_relay)
		return HOOK_CANNOT_CREATE_START_RELAY;

	raven_jmp(target_func, start_relay);
	raven_nop(PTROFFSET(target_func, jmp_size), mangled_bytes);

    return 0;
}
