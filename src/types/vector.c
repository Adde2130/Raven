#include "types.h"

#include <string.h>

#ifdef VECTOR_DEBUG
#include <stdio.h>
#endif

struct Vector {
    void* items;
    uint32_t vector_size;
    uint32_t item_count;
    uint32_t item_size;
};

Vector* vector_create(uint32_t vector_size, uint32_t item_size) {
    Vector* vector = malloc(sizeof(Vector));
    vector->items  = malloc(vector_size * item_size);
    vector->vector_size = vector_size;
    vector->item_count = 0;
    vector->item_size = item_size;

#ifdef VECTOR_DEBUG
    printf("Created a vector on the heap with vector_size %u at 0x%p\n", vector_size, vector->items);
#endif

    return vector;
}

void vector_free(Vector* vec) {
    free(vec->items);
    vec->items = NULL;
    free(vec);
    vec = NULL;
}

void vector_add(Vector* vec, void* item) {
    vec->item_count++;
    if(vec->item_count > vec->vector_size) {
#ifdef VECTOR_DEBUG
        void* OLD_LOCATION = vec->items;
#endif

        vec->items = realloc(vec->items, vec->vector_size * 2 * vec->item_size);
        vec->vector_size *= 2;

#ifdef VECTOR_DEBUG
        printf("Reallocating vector items from 0x%p to 0x%p, with the new vector_size %u\n", OLD_LOCATION, vec->items, vec->vector_size);
#endif

    }

    memcpy((char*)vec->items + vec->item_size * (vec->item_count - 1), item, vec->item_size);

#ifdef VECTOR_DEBUG
    printf("Vector items at 0x%p appended the new item_count %u\n", vec->items, vec->item_count);
#endif

}

void vector_remove(Vector* vec, void* item) {
    for(uint32_t i = 0; i < vec->item_count; i++){
        if(memcmp(item, (char*)vec->items + i * vec->item_size, vec->item_size) == 0) {
            if(i != vec->item_count - 1) 
                memmove( (char*)vec->items + i * vec->item_size, (char*)vec->items  + (i + 1) * vec->item_size, (vec->item_count - i - 1) * vec->item_size);

            vec->item_count--;
            break;
        }
    }
}

void* vector_get(Vector* vec, uint32_t index) {
#ifdef VECTOR_DEBUG
    if(index >= vec->item_count)
        printf("vector_get: vector - 0x%p | index - %d | (r) value - INDEX TOO LARGE\n", vec, index);
    else
        printf("vector_get: vector - 0x%p | index - %d | (r) value - 0x%p\n", vec, index, (char*)vec->items + index * vec->item_size);
#endif

    if(index >= vec->item_count) return NULL;
    return (char*)vec->items + index * vec->item_size;
}

uint32_t vector_count(Vector* vec){
    return vec->item_count;
}

uint32_t vector_item_size(Vector* vec) {
    return vec->item_size;
}

bool vector_contains(Vector* vec, void* item) {
    for(uint32_t i = 0; i < vec->item_count; i++)
        if(memcmp(item, (char*)vec->items + i * vec->item_size, vec->item_size) == 0)
            return true;
    return false;
}

void vector_foreach(Vector* vec, cbfp_t func_ptr) {
#ifdef VECTOR_DEBUG
    printf("vector_foreach: vec - 0x%p | item_count - %u | function - 0x%p\n", vec->items, vec->item_count, func_ptr);
#endif

    for(uint32_t i = 0; i < vec->item_count; i++)
        func_ptr((char*)vec->items + i * vec->item_size);

}

void vector_foreach_va(Vector* vec, vafp_t func_ptr, ...){
#ifdef VECTOR_DEBUG
    printf("vector_foreach_va: vec - 0x%p | item_count - %u | function - 0x%p\n", vec->items, vec->item_count, func_ptr);
#endif

    va_list args; 
    for(uint32_t i = 0; i < vec->item_count; i++) {
        va_start(args, func_ptr);
        func_ptr((char*)vec->items + i * vec->item_size, args);
        va_end(args);
    }

}