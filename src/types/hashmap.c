#include "types.h"

#ifdef HASHMAP_DEBUG
#include <stdio.h>
#endif

#include <string.h>

const uint32_t DEFAULT_SIZE = 8;

uint64_t hash_str(const char* str) {
    uint64_t hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

typedef struct {
    char* key;
    void* value;
} item_t;

struct Hashmap {
    item_t** items;
    uint32_t item_count;
    uint32_t size;
};

Hashmap* hashmap_create() {
    Hashmap* map = malloc(sizeof(Hashmap));
    item_t** items = malloc(sizeof(item_t*) * DEFAULT_SIZE);
    memset(items, 0, sizeof(item_t*) * DEFAULT_SIZE);
    map->items = items;
    map->item_count = 0;
    map->size = DEFAULT_SIZE;

#ifdef HASHMAP_DEBUG
    printf("hashmap_create: (r) location - 0x%p\n", map);
#endif

    return map;
}

void hashmap_resize(Hashmap* map, uint32_t new_size) {
#ifdef HASHMAP_DEBUG
    printf("Attempting to resize the Hashmap at 0x%p to the size %u", map, new_size);
#endif

    uint32_t old_size = map->size;
    item_t** new_items = malloc(sizeof(item_t) * new_size);
    memset(new_items, 0, sizeof(item_t*) * new_size);
    for(uint32_t i = 0; i < old_size; i++){
        if(map->items[i] == NULL)
            continue;

        uint64_t hash = hash_str(map->items[i]->key) % new_size;
        while(new_items[hash] != NULL) hash++;
        new_items[hash] = map->items[i];
    }

    free(map->items);
    map->items = new_items;
    map->size = new_size;
}

void hashmap_insert(Hashmap* map, const char* key, void* value){
#ifdef HASHMAP_DEBUG
    printf("hashmap_insert: map - 0x%p | key - \"%s\" | value - 0x%p\n", map, key, value);
#endif

    item_t* item = malloc(sizeof(item_t));
    item->key = malloc(strlen(key));
    strcpy(item->key, key);
    item->value = value;

    uint64_t hash = hash_str(key) % map->size;
    uint64_t start_hash = hash;

    while(map->items[hash] != NULL) {
        hash++;
        hash %= map->size;
        if(hash == start_hash)
            hashmap_resize(map, map->size * 2);
    }

    map->items[hash] = item;
    map->item_count++;
}

void* hashmap_get(Hashmap* map, const char* key){
    uint64_t hash = hash_str(key) % map->size;
    uint64_t start_hash = hash;
    void* value = NULL;
    while(map->items[hash] != NULL) {
        if(strcmp(map->items[hash]->key, key) == 0) {
            value = map->items[hash]->value;
            break;
        }

        hash++;

        hash %= map->size;

        if(hash == start_hash)
            break;
    }

#ifdef HASHMAP_DEBUG
    if(value)
        printf("hashmap_get: map - 0x%p | key - \"%s\" | (r) value - 0x%p\n", map, key, value);
    else
        printf("hashmap_get: map - 0x%p | key - \"%s\" | (r) value - NULL (ITEM NOT FOUND)\n", map, key);
#endif
    return value;
}

void hashmap_remove(Hashmap* map, const char* key) {
    uint64_t hash = hash_str(key) % map->size;
    uint64_t start_hash = hash;
    while(map->items[hash] != NULL) {
        if(strcmp(map->items[hash]->key, key) == 0) {
            map->items[hash] = NULL;
            map->item_count--;
            break;
        }

        hash++;

        hash %= map->size;

        if(hash == start_hash)
            break;
    }
}

uint32_t hashmap_count(Hashmap* map) {
    return map->item_count;
}

void hashmap_foreach(Hashmap* map, cbfp_t callback) {
#ifdef HASHMAP_DEBUG
    printf("hashmap_foreach: map - 0x%p | item_count - %u | callback - 0x%p\n", map->items, map->item_count, callback);
#endif

    uint32_t item_index = 0;
    for(uint32_t i = 0; item_index <  map->item_count; i++) {
        if(map->items[i] == NULL)
            continue;
        callback(map->items[i]);
        item_index++;
    }
}

char** hashmap_keys(Hashmap* map) {
    char** keys = malloc(map->item_count * sizeof(char**));
    uint32_t item_index = 0;
    for(uint32_t i = 0; item_index <  map->item_count; i++) {
        if(map->items[i] == NULL)
            continue;
        keys[item_index] = map->items[i]->key;
        item_index++;
    }

    return keys;
}

bool hashmap_has_key(Hashmap* map, const char* key) {
    uint64_t hash = hash_str(key) % map->size;
    uint64_t start_hash = hash;
    while(map->items[hash] != NULL) {
        if(strcmp(map->items[hash]->key, key) == 0) {
            return true;
        }

        hash++;

        hash %= map->size;

        if(hash == start_hash)
            break;
    }

    return false;
}

void hashmap_free(Hashmap* map) {
    for(uint32_t i = 0; i < map->size; i++)
        if(map->items[i] != NULL)
            free(map->items[i]);
    free(map->items);
    free(map);
}