#ifndef RAVEN_ASSEMBLY_H
#define RAVEN_ASSEMBLY_H

#include "types.h"

// REFERENCE: 32-bit: http://ref.x86asm.net/coder32.html
//            64-bit: http://ref.x86asm.net/coder64.html




/*  ------------------------ MODR/M ------------------------

    _______________________________________________________
   |  Bit  |  7  |  6  |  5  |  4  |  3  |  2  |  1  |  0  |
   | Usage |    MOD    | REG/OPCODE EXTENSION  |    RM     |
    ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

        Reference: https://en.wikipedia.org/wiki/ModR/M 
*/





/* --------------- x86 ASM OPCODES --------------- */
#define NOP       0x90
#define INT3      0xCC
#define JMP_REL32 0xE9
#define RET_N	  0xC2
#define RET		  0xC3


/* ------------ INC 32-BIT ------------ */
#define INC_EAX   0x40
#define INC_ECX   0x41
#define INC_EDX   0x42
#define INC_EBX   0x43
#define INC_ESP   0x44
#define INC_EBP   0x45
#define INC_ESI   0x46
#define INC_EDI   0x47


/* ------------ DEC 32-BIT ------------ */
#define DEC_EAX   0x48
#define DEC_ECX   0x49
#define DEC_EDX   0x4A
#define DEC_EBX   0x4B
#define DEC_ESP   0x4C
#define DEC_EBP   0x4D
#define DEC_ESI   0x4E
#define DEC_EDI   0x4F


/* ----------- REX PREFIXES ----------- */
#define REX0      0x40
#define REX1      0x41
#define REX2      0x42
#define REX3      0x43
#define REX4      0x44
#define REX5      0x45
#define REX6      0x46
#define REX7      0x47
#define REX8      0x48 
#define REX9      0x49
#define REXA      0x4A
#define REXB      0x4B
#define REXC      0x4C
#define REXD      0x4D
#define REXE      0x4E
#define REXF      0x4F


/* -------------- PUSH -------------- */
#define PUSH_EAX  0x50
#define PUSH_ECX  0x51
#define PUSH_EDX  0x52
#define PUSH_EBX  0x53
#define PUSH_ESP  0x54
#define PUSH_EBP  0x55
#define PUSH_ESI  0x56
#define PUSH_EDI  0x57

#define PUSH_RAX  0x50
#define PUSH_RCX  0x51
#define PUSH_RDX  0x52
#define PUSH_RBX  0x53
#define PUSH_RSP  0x54
#define PUSH_RBP  0x55
#define PUSH_RSI  0x56
#define PUSH_RDI  0x57


/* -------------- POP -------------- */
#define POP_EAX   0x58
#define POP_ECX   0x59
#define POP_EDX   0x5A
#define POP_EBX   0x5B
#define POP_ESP   0x5C
#define POP_EBP   0x5D
#define POP_ESI   0x5E
#define POP_EDI   0x5F

#define POP_RAX   0x58
#define POP_RCX   0x59
#define POP_RDX   0x5A
#define POP_RBX   0x5B
#define POP_RSP   0x5C
#define POP_RBP   0x5D
#define POP_RSI   0x5E
#define POP_RDI   0x5F

#define PUSHAD	  0x60
#define POPAD	  0x61

/* -------------- MOV -------------- */
#define MOV_AL    0xB0
#define MOV_AH    0xB1
#define MOV_DL    0xB2
#define MOV_DH    0xB3
#define MOV_CL    0xB4
#define MOV_CH    0xB5
#define MOV_BL    0xB6
#define MOV_BH    0xB7

#define MOV_EAX   0xB8
#define MOV_ECX   0xB9
#define MOV_EDX   0xBA
#define MOV_EBX   0xBB
#define MOV_ESP   0xBC
#define MOV_EBP   0xBD
#define MOV_ESI   0xBE
#define MOV_EDI   0xBF


#define CALL	  0xE8


#define MODRM     0xFF

#define ISGARBAGE(x) ((x == INT3) || (x == NOP))

#define MAX_REL_JMP 2147483647

void resolve_mangled_bytes(void* original_address, void* target_address, uint8_t byte_count, byte_t* mangled_bytes);

/**
 * @brief Creates a relative JMP instruction at the target.
 *
 * @param [in] from	  From where to jump
 * @param [in] to     Where to jump
 */
uint8_t raven_jmp(void* from, void* to);

/**
 * @brief Creates asm code to shift `count` number of values
 * 		  `shift_amount` number of spaces up the stack.
 *
 * @param [in] 	count			The number of values to shift
 * @param [in] 	shift_amount	The number of slots to shift it
 * @param [out]	asm_out			The generated asm code
 *
 * @remarks This function does not generate a POP EAX for you.
 * 			It is expected that you add this yourself to the 
 * 			assembly code. 
 */
int raven_shift_stack(int count, int shift_amount, byte_t* asm_out);

#endif
