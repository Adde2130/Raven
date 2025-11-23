.intel_syntax noprefix

example:
	push EAX
	push EBX
#	...			<--- JMP to start_relay somewhere in here:
	pop EAX
	pop EBX

	ret

	
# CREATE THIS CLOSE TO THE ORIGINAL FUNC
start_relay:
	push EAX
	mov EAX, end_relay
	jmp EAX


# CREATE THIS CLOSE TO THE DETOUR FUNC
end_relay:
	pop 	EAX

	pusha

	# Fix the stack for the float registers since it must be 16-aligned
	# Since ECX is used for __thiscalls (where we might want to interact
	# with the object), please use other registers
	mov		eax, esp
	and		eax, 0xF

	sub		esp, 512
	sub		esp, eax
	fxsave	[esp]

	push	eax

	
	call 	DETOUR_FUNC


	pop		eax

	fxrstor	[esp]
	add		esp, 512
	add		esp, eax

	popa

	push	EAX
	mov		EAX, trampoline
	jmp		EAX

# CREATE THIS CLOSE TO THE ORIGINAL FUNC
trampoline:
	pop		EAX
	# OVERWRITTEN INSTRUCTIO HERE
	jmp		original_function_continue
