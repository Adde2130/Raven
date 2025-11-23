.intel_syntax noprefix

example:
	push EAX # <-- Replaced with our JMP
	push EBX
	pop EAX
	pop EBX

	ret

	
# CREATE THIS CLOSE TO THE ORIGINAL FUNC
start_relay:
	push EAX
	mov EAX, end_relay
	jmp EAX


# CREATE THIS CLOSE TO THE HOOK FUNC
# Goal: First pass the stack parameters, then the registers. So:
#
# Save all registers (pusha)
# Get the part of the stack that needs to be pushed again
		
end_relay_32:
	pop 	EAX

	pushad

	mov		ECX, ESP
	sub		ECX, 0x20

	push 	[ECX + 8]
	push	[ECX + 4]

	call 	my_func

	popad

	ret
	
# For each parameter, push

	
# CREATE THIS CLOSE TO THE ORIGINAL FUNC
trampoline:
	pop		EAX
	# OVERWRITTEN INSTRUCTIO HERE
	jmp		original_function_continue
