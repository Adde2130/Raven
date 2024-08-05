#include "raven_detour.h"

int8_t detour(void* target, void* detour_func, uint8_t mangled_bytes, char* original_bytes) {
	
}

void RAVENDETOUR example_detour() {
	regsize_t IN_EAX; 
	regsize_t IN_ECX; 
	regsize_t IN_EDX; 
	regsize_t IN_EBX; 
	regsize_t IN_ESP; 
	regsize_t IN_EBP; 
	regsize_t IN_ESI; 
	regsize_t IN_EDI; 

	asm volatile(
		"pushal"
	);

	infobox("WE ARE HERE! EAX: %X", IN_ECX);

	asm volatile(
		"popal"
	);

}
