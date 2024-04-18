/**
 * Personal file for some higher level types likes hashmaps
 * and vectors. Very WIP.
 */

#ifndef TYPES_H
#define TYPES_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>

#define byte_t unsigned char

/* ------ Function pointer types ------ */
typedef bool (*rfp_t )(int32_t);          // Render function pointer
typedef void (*cbfp_t)(void*);            // Callback function pointer
typedef void (*vafp_t)(void*, va_list);   // Variable argument function pointer

/* --------- Vector datatype ---------- */
// #define VECTOR_DEBUG
typedef struct Vector Vector;
Vector*  vector_create(uint32_t vector_size, uint32_t item_size);
void     vector_free(Vector* vec);
void     vector_add(Vector* vec, void* item);
void     vector_remove(Vector* vec, void* item);
void*    vector_get(Vector* vec, uint32_t index);
uint32_t vector_count(Vector* vec);
uint32_t vector_item_size(Vector* vec);
bool     vector_contains(Vector* vec, void* item);
void     vector_foreach(Vector* vec, cbfp_t func_ptr);
void     vector_foreach_va(Vector* vec, vafp_t func_ptr, ...);

/* --------- Hashmap datatype ---------- */
// #define HASHMAP_DEBUG
typedef struct Hashmap Hashmap;
Hashmap* hashmap_create();
void     hashmap_insert(Hashmap* map, const char* key, void* value);
void*    hashmap_get(Hashmap* map, const char* key);
void     hashmap_foreach(Hashmap* map, cbfp_t callback);
void     hashmap_remove(Hashmap* map, const char* key);
uint32_t hashmap_count(Hashmap* map);
char**   hashmap_keys(Hashmap* map); // MALLOCS!!!!!
bool     hashmap_has_key(Hashmap* map, const char* key);

/* ---------- Misc. datatypes ---------- */

#endif