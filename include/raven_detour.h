#ifndef RAVEN_DETOUR_H
#define RAVEN_DETOUR_H

typedef regsize_t int32_t;

#ifdef __GNUC__
#define RAVENDETOUR __attribute__((naked))

#ifndef _WIN64
#define DETOUR_PRESERVE_REGISTERS 	regsize_t IN_EAX; \
									regsize_t IN_ECX; \
									asm volatile( \
										"pushal"
										"movl %%eax, %%ebp"
										"subl %%eax, $0x20" // Base address from previous function
										"
#endif

#endif
