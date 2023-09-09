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
    vector->items  = malloc(sizeof(void*) * vector_size * item_size);
    vector->vector_size = vector_size;
    vector->item_count = 0;
    vector->item_size = item_size;

#ifdef VECTOR_DEBUG
    printf("Created a vector on the heap with vector_size %u at 0x%p\n", vector_size, vector->items);
#endif

    return vector;
}

Vector vector_create_stack(uint32_t vector_size, uint32_t item_size) {
    Vector vector = {0};
    vector.items  = malloc(sizeof(void*) * vector_size);
    vector.vector_size = vector_size;
    vector.item_count = 0;
    vector.item_size = item_size;

#ifdef VECTOR_DEBUG
    printf("Created a vector on the stack with vector_size %u at 0x%p\n", vector_size, vector.items);
#endif

    return vector;
}

void vector_free(Vector* vec) {
    free(vec->items);
    free(vec);
}

void vector_add(Vector* vec, void* item) {
    vec->item_count++;
    if(vec->item_count > vec->vector_size) {
#ifdef VECTOR_DEBUG
        void* LOCATION = vec->items;
#endif

        vec->items = realloc(vec->items, vec->vector_size * 2);
        vec->vector_size *= 2;

#ifdef VECTOR_DEBUG
        printf("Reallocating vector items from 0x%p to 0x%p, with the new vector_size %u\n", LOCATION, vec->items, vec->vector_size);
#endif

    }

#ifdef VECTOR_DEBUG
    printf("Vector items at 0x%p appended the new item_count %u\n", vec->items, vec->item_count);
#endif

    memcpy(vec->items + vec->item_size * (vec->item_count - 1), item, item, vec->item_size);
}

//  TODO: Fix 
// void vector_remove(Vector* vec, void* item) {
//     bool found = false;
//     for(uint32_t i = 0; i < vec->item_count; i++){
//         if(vec->items[i] == item)
//             found = true;

//         if(found) {
//             if(i == vec->item_count - 1)
//                 vec->items[i] = NULL;
//             else
//                 vec->items[i] = vec->items[i + 1];
//         }
//     }

//     if(found)
//         vec->item_count--;
// }

void* vector_get(Vector * vec, uint32_t index) {
    if(index >= vec->item_count) return NULL;
    return vec->items + index * vec->item_size;
}

uint32_t vector_count(Vector* vec){
    return vec->item_count;
}

uint32_t vector_item_size(Vector* vec) {
    return vec->item_size;
}

void vector_foreach(Vector* vec, cbfp_t func_ptr) {
#ifdef VECTOR_DEBUG
    printf("vector_foreach: vec - 0x%p | item_count - %u | function - 0x%p\n", vec->items, vec->item_count, func_ptr);
#endif

    for(uint32_t i = 0; i < vec->item_count; i++)
        func_ptr(vec->items + vec->item_count * (vec->item_size - 1));

}

void vector_foreach_va(Vector* vec, vafp_t func_ptr, ...){
#ifdef VECTOR_DEBUG
    printf("vector_foreach_va: vec - 0x%p | item_count - %u | function - 0x%p\n", vec->items, vec->item_count, func_ptr);
#endif

    va_list args; 
    for(uint32_t i = 0; i < vec->item_count; i++) {
        va_start(args, func_ptr);
        func_ptr(vec->items + vec->item_count * (vec->item_size - 1), args);
        va_end(args);
    }

}