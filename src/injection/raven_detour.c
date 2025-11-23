/* TODO: 64-bit detours! */

#include "raven.h"
#include "raven_assembly.h"

#ifdef _WIN64
#define ADDRESS_SIZE 8
#else
#define ADDRESS_SIZE 4
#endif


static const int JMP_SIZE = 5;

void* __create_start_relay(void* original_func, void* end_relay){
	/*
	 *	CREATE THE FOLLOWING ASM FUNCTION:
	 *
	 *	start_relay:
	 *		push EAX
	 *		mov EAX, end_relay
	 *		jmp EAX
	 *
	 */

#ifdef _WIN64
	int relay_address_index = 3;
#else
	int relay_address_index = 2;
#endif

    byte_t bytes[] = {
        PUSH_RAX,
#ifdef _WIN64
        REX8, MOV_EAX, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0's are the address of the hook
#else
		MOV_EAX, 0x00, 0x00, 0x00, 0x00,
#endif
        MODRM, 0xE0, // E0 -> E = JMP, 0 = RAX
    };

    void* relay_address = find_unallocated_memory(original_func, sizeof(bytes));
    if(!relay_address)
        return NULL;

    memcpy(bytes + relay_address_index, &end_relay, ADDRESS_SIZE);
    memcpy(relay_address, bytes, sizeof(bytes));

	DWORD oldprotect;
	VirtualProtect(relay_address, sizeof(bytes), PAGE_EXECUTE, &oldprotect);

    return relay_address;
}

void* __create_end_relay32(void* detour_func, void* original_func_trampoline) {
	/* 	
	 *	CREATE THE FOLLOWING ASM FUNCTION:
	 *
	 *  end_relay:
	 * 		pop 	EAX
	 *
	 * 		pushad
	 *
	 * 		mov		ebx, esp
	 * 		add		ebx, 0x20 <-- get the original stack pointer and pass it
	 *
	 * 		mov		eax, esp
	 * 		and		eax, 0xf  <-- get the offset from 16
	 *
	 * 		sub		esp, 512  
	 * 		sub		esp, eax  <-- fxsave must be 0x10 aligned
	 * 		fxsave	[esp]
	 *
	 * 		push 	eax
	 *
	 * 		push	ebx			<-- arg1 = original esp
	 * 		call 	DETOUR_FUNC <-- called with __cdecl calling convention
	 * 		add 	esp, 4
	 *
	 *		pop 	eax
	 *
	 * 		fxrstor	[esp]
	 * 		add		esp, 512
	 * 		add 	esp, eax
	 *
	 * 		popad
	 * 		
	 * 		push	EAX
	 * 		mov		EAX, TRAMPOLINE
	 * 		jmp		EAX
	 *
	 */

	int call_index = 27;

    byte_t bytes[] = {
        POP_EAX,

		PUSHAD,

		0x89, 0xE3,							 // mov 	ebx, esp
		0x83, 0xC3, 0x20,					 // add 	ebx, 0x20
											 
		0x89, 0xe0,                   		 // mov 	eax, esp
		0x83, 0xe0, 0x0f,                	 // and 	eax, 0xf

		0x81, 0xEC, 0x00, 0x02, 0x00, 0x00,  // sub 	esp, 512
		0x29, 0xc4,                   		 // sub 	esp, eax								
		0x0f, 0xae, 0x04, 0x24,			  	 // fxsave 	[esp]

		PUSH_EAX,
		
		PUSH_EBX,
        CALL, 0x00, 0x00, 0x00, 0x00,	  	 // REPLACE BYTES WITH RELATIVE FUNCTION OFFSET
		0x83, 0xC4, 0x04,					 // add		esp, 4
											 

		POP_RAX,

		0x0f, 0xae, 0x0c, 0x24,              // fxrstor [esp]
		0x81, 0xc4, 0x00, 0x02, 0x00, 0x00,  // add 	esp, 512
		0x01, 0xc4,                      	 // add 	esp, eax

		POPAD,							  	 // popa
		

		// TODO: since it is 32-bit, just relative jmp?
		PUSH_EAX,
		MOV_EAX, 0x00, 0x00, 0x00, 0x00,
		MODRM, 0xE0							// jmp eax
    };

	int jmp_index = sizeof(bytes) - 6;

    void* relay_address = find_unallocated_memory(detour_func, sizeof(bytes));
	if(!relay_address)
		return NULL;

	intptr_t detour_func_offset = (intptr_t)detour_func - (intptr_t)relay_address - call_index - 4;
	memcpy(bytes + call_index, &detour_func_offset, 4);
	memcpy(bytes + jmp_index, &original_func_trampoline, ADDRESS_SIZE); 
	memcpy(relay_address, bytes, sizeof(bytes));

	DWORD oldprotect;
	VirtualProtect(relay_address, sizeof(bytes), PAGE_EXECUTE, &oldprotect);

    return relay_address;
}

static void* __create_function_trampoline(void* original_address, uint8_t mangled_bytes) {
	const int POP_RAX_CONST = POP_RAX;
	
	int trampoline_size =
		1 + 					 	// pop EAX
		JMP_SIZE + mangled_bytes + 	// overwritten instruction
		JMP_SIZE;					// jmp original_function_continuation

	void* trampoline = find_unallocated_memory(original_address, trampoline_size);
	if(!trampoline)
		return NULL;

	
	byte_t jmp_instruction[] = {
		JMP_REL32, 0x00, 0x00, 0x00, 0x00
	};

	int32_t relative_offset = 
			(intptr_t)original_address + JMP_SIZE + mangled_bytes
				- ((intptr_t)trampoline + trampoline_size);
	
	memcpy(jmp_instruction + 1, &relative_offset, 4);
	memcpy(trampoline, &POP_RAX_CONST, 1);


	byte_t bytes[JMP_SIZE + mangled_bytes];
	resolve_mangled_bytes(original_address, trampoline + 1, JMP_SIZE + mangled_bytes, bytes);
	
	memcpy(trampoline + 1, bytes, JMP_SIZE + mangled_bytes);


	memcpy(trampoline + 1 + JMP_SIZE + mangled_bytes, jmp_instruction, JMP_SIZE);

	DWORD oldprotect;
	VirtualProtect(trampoline, trampoline_size, PAGE_EXECUTE, &oldprotect);

	return trampoline;
}

DETOUR_ERROR raven_detour(void* target, void* detour_func, uint8_t mangled_bytes, char** original_bytes) {
	const int NOP_CONST = NOP;

	void* trampoline = __create_function_trampoline(target, mangled_bytes);
	if(!trampoline)
		return DETOUR_CANNOT_CREATE_TRAMPOLINE;

	void* end_relay = __create_end_relay32(detour_func, trampoline);
	if(!end_relay)
		return DETOUR_CANNOT_CREATE_END_RELAY;
	
	void* start_relay = __create_start_relay(target, end_relay);
	if(!start_relay)
		return DETOUR_CANNOT_CREATE_START_RELAY;
	
	
	int32_t function_offset = (intptr_t)start_relay - (intptr_t)target - JMP_SIZE;
	byte_t jmp_instruction[] = {
		JMP_REL32, 0x00, 0x00, 0x00, 0x00
	};

	memcpy(jmp_instruction + 1, &function_offset, 4);
	protected_write(target, jmp_instruction, JMP_SIZE);

	if(original_bytes != NULL)
		protected_write(original_bytes, target, JMP_SIZE + mangled_bytes);

	for(int i = 0; i < mangled_bytes; i++)
		protected_write(PTROFFSET(target, JMP_SIZE + i), &NOP_CONST, 1);

	return DETOUR_SUCCESS;
}

