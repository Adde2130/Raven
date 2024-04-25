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
#include <stdio.h>

#define byte_t unsigned char

/* ------ Function pointer types ------ */
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
typedef struct   __BytesHashmap  __BytesHashmap;
typedef          __BytesHashmap    Hashmap;
__BytesHashmap*    hashmap_create(size_t key_size, size_t value_size);
void             __hashmap_insert_bytes(__BytesHashmap* map, const void* key, const void* value);
void*            __hashmap_get_bytes(const __BytesHashmap* map, const void* key);
bool             __hashmap_remove_bytes(__BytesHashmap* map, const void* key);
void**           __hashmap_keys_bytes(const __BytesHashmap* map); // MALLOCS!!!!!
bool             __hashmap_has_key_bytes(const __BytesHashmap* map, const void* key);
void             __hashmap_print_contents_bytes(const __BytesHashmap* map, FILE* stream);

typedef struct   __StringHashmap __StringHashmap;
typedef          __StringHashmap   StringHashmap;
__StringHashmap*   hashmap_create_string(size_t value_size);
void             __hashmap_insert_string(__StringHashmap* map, const void* key, const void* value);
void*            __hashmap_get_string(const __StringHashmap* map, const void* key);
bool             __hashmap_remove_string(__StringHashmap* map, const void* key);
char**           __hashmap_keys_string(const __StringHashmap* map); // MALLOCS!!!!!
bool             __hashmap_has_key_string(const __StringHashmap* map, const void* key);
void             __hashmap_print_contents_string(const __StringHashmap* map, FILE* stream);

/* Apparently there is a "bug" with the C standard that requires EVERY part of the macro to be valid
   with the current type, even if the evaluated part is correct. Therefore ugly casting is needed to
   avoid compiler warnings :/ */

#define hashmap_insert(p_map, key, value) _Generic((p_map), __BytesHashmap*: __hashmap_insert_bytes((__BytesHashmap*)p_map, key, value), __StringHashmap*: __hashmap_insert_string((__StringHashmap*)p_map, key, value))
#define hashmap_get(p_map, key) _Generic((p_map), __BytesHashmap*: __hashmap_get_bytes((__BytesHashmap*)p_map, key), __StringHashmap*: __hashmap_get_string((__StringHashmap*)p_map, key))
#define hashmap_remove(p_map, key) _Generic((p_map), __BytesHashmap*: __hashmap_remove_bytes((__BytesHashmap*)p_map, key), __StringHashmap*: __hashmap_remove_string((__StringHashmap*)p_map, key))
#define hashmap_keys(p_map, key) _Generic((p_map), __BytesHashmap*: __hashmap_keys_bytes((__BytesHashmap*)p_map), __StringHashmap*: __hashmap_keys_string((__StringHashmap*)p_map))
#define hashmap_has_key(p_map, key) _Generic((p_map), __BytesHashmap*: __hashmap_has_key_bytes((__BytesHashmap*)p_map, key), __StringHashmap*: __hashmap_has_key_string((__StringHashmap*)p_map, key))
#define hashmap_print_contents(p_map) _Generic((p_map), __BytesHashmap*: __hashmap_print_contents_bytes((__BytesHashmap*)p_map), __StringHashmap*: __hashmap_print_contents_string((__StringHashmap*)p_map))


void     hashmap_foreach(Hashmap* map, cbfp_t callback);
uint64_t hashmap_count(const Hashmap* map);

/* ---------- Misc. datatypes ---------- */

#endif