#include "types.h"

#include <string.h>

typedef uint64_t (*__p_hash_function)(const void*);

const uint32_t DEFAULT_SIZE = 8;

void __hashmap_resize(Hashmap*, uint32_t, __p_hash_function);

/* ------------------- BYTE HASHMAP ------------------- */

//TODO: Better hash
uint64_t __hash_key(const void* key) {
    return (uintptr_t)key;
}

struct __BytesHashmap {
    void** items;
    uint64_t item_count;
    uint64_t max_items;
    size_t key_size;
    size_t value_size;
};

__BytesHashmap* hashmap_create(size_t key_size, size_t value_size) {
    if(key_size == 0 || value_size == 0)
        return NULL;

    __BytesHashmap* map = malloc(sizeof(__BytesHashmap));
    void** items = malloc(sizeof(void*) * DEFAULT_SIZE);    

    memset(items, 0, sizeof(void*) * DEFAULT_SIZE);
    map->items = items;
    map->item_count = 0;

    map->key_size = key_size;
    map->value_size = value_size;

    map->max_items = DEFAULT_SIZE;

#ifdef HASHMAP_DEBUG
    printf("hashmap_create: (r) location - 0x%p\n", map);
#endif

    return map;
}

void __hashmap_insert_bytes(__BytesHashmap* map, const void* key, const void* value) {
    void* item = malloc(map->key_size + map->value_size);
    if(!item)
        return;

    void* item_key = item;
    void* item_value = ((char*)item) + map->key_size;

    memcpy(item_key, key, map->key_size);
    memcpy(item_value, value, map->value_size);

    uint64_t hash = __hash_key(key) % map->max_items;
    uint64_t start_hash = hash;

    while(map->items[hash] != NULL) {
        if(memcmp(key, map->items[hash], map->key_size) == 0) {
            memcpy((char*)(map->items[hash]) + map->key_size, value, map->value_size);
            free(item);
            return;
        }

        hash++;
        hash %= map->max_items;
        if(hash == start_hash)
            __hashmap_resize(map, map->max_items * 2, __hash_key);
    }
    
    map->items[hash] = item;
    map->item_count++;
}

void* __hashmap_get_bytes(const __BytesHashmap* map, const void* key){
    uint64_t hash = __hash_key(key) % map->max_items;
    uint64_t start_hash = hash;
    void* value = NULL;
    while(map->items[hash] != NULL) {
        if(memcmp(map->items[hash], key, map->key_size) == 0) {
            value = (char*)map->items[hash] + sizeof(char*);
            break;
        }

        hash++;
        hash %= map->max_items;

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

bool __hashmap_remove_bytes(__BytesHashmap* map, const void* key) {
    uint64_t hash = __hash_key(key) % map->max_items;
    uint64_t start_hash = hash;
    while(map->items[hash] != NULL) {
        if(memcmp(map->items[hash], key, map->key_size) == 0) {
            free(map->items[hash]);
            map->items[hash] = NULL;
            map->item_count--;
            return true;;
        }

        hash++;

        hash %= map->max_items;

        if(hash == start_hash)
            break;
    }

    return false;
}

void** __hashmap_keys_bytes(const __BytesHashmap* map) {
    void** keys = malloc(map->item_count * map->key_size);
    uint32_t item_index = 0;
    for(uint32_t i = 0; item_index <  map->item_count; i++) {
        if(map->items[i] == NULL)
            continue;
        memcpy(keys[item_index], map->items[i], map->key_size);
        item_index++;
    }

    return keys;
}

bool __hashmap_has_key_bytes(const __BytesHashmap* map, const void* key) {
    uint64_t hash = __hash_key(key) % map->max_items;
    uint64_t start_hash = hash;
    while(map->items[hash] != NULL) {
        if(memcmp(map->items[hash], key, map->key_size) == 0) {
            return true;
        }

        hash++;

        hash %= map->max_items;

        if(hash == start_hash)
            break;
    }

    return false;
}

void __hashmap_free_bytes(__BytesHashmap* map) {
    for(uint32_t i = 0; i < map->max_items; i++)
        if(map->items[i] != NULL)
            free(map->items[i]);
    free(map->items);
    free(map);
}

void __hashmap_print_contents_bytes(const __BytesHashmap* map, FILE* stream) {
    for(uint64_t i = 0; i < map->max_items; i++) {
        if(map->items[i] == NULL)
            continue;

        fprintf(stream, "> Index %llu, 0x%p:\n", i, ((char*)(map->items) + (i * sizeof(void*))));
        fprintf(stream, "    > 0x%p\n", map->items[i]);
        fprintf(stream, "        > ");
        for(size_t j = 0; j < map->key_size; j++)
            fprintf(stream, "%02X ", *((unsigned char*)(map->items[i]) + j));
        fprintf(stream, " | ");
        for(size_t j = 0; j < map->value_size; j++)
            fprintf(stream, "%02X ", *((unsigned char*)(map->items[i]) + j + map->key_size));
        fprintf(stream, "\n\n");
    }
}

/* ------------------- STRING HASHMAP ------------------- */

uint64_t __hash_str(const void* key) {
    uint64_t hash = 5381;
    const char* str = key;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

struct __StringHashmap {
    void** items;
    uint32_t item_count;
    uint64_t max_items;
    size_t value_size;
};

__StringHashmap* hashmap_create_string(size_t value_size) {
    if(value_size == 0)
        return NULL;

    __StringHashmap* map = malloc(sizeof(__StringHashmap));
    void** items = malloc(sizeof(void*) * DEFAULT_SIZE);    

    memset(items, 0, sizeof(void*) * DEFAULT_SIZE);
    map->items = items;
    map->item_count = 0;

    map->value_size = value_size;

    map->max_items = DEFAULT_SIZE;

#ifdef HASHMAP_DEBUG
    printf("hashmap_create: (r) location - 0x%p\n", map);
#endif

    return map;
}

void __hashmap_insert_string(__StringHashmap* map, const void* key, const void* value){
#ifdef HASHMAP_DEBUG
    printf("hashmap_insert: map - 0x%p | key - \"%s\" | value - 0x%p\n", map, key, value);
#endif

    void* item = malloc(sizeof(char*) + map->value_size);
    if(!item)
        return;

    void* item_key = malloc(strlen(key) + 1);
    if(!item_key)
        return;

    void* item_value = (char*)item + sizeof(char*);

    strcpy(item_key, key);
    memcpy(item, &item_key, sizeof(char*));
    memcpy(item_value, value, map->value_size);

    uint64_t hash = __hash_str(key) % map->max_items;
    uint64_t start_hash = hash;

    while(map->items[hash] != NULL) {
        if(strcmp(*(char**)map->items[hash], key) == 0) {
            memcpy((char*)map->items[hash] + sizeof(char*), value, map->value_size);
            free(item_key);
            free(item);
            return;
        }

        hash++;
        hash %= map->max_items;
        if(hash == start_hash)
            __hashmap_resize((__BytesHashmap*)map, map->max_items * 2, __hash_str);
    }
    
    map->items[hash] = item;
    map->item_count++;
}

void* __hashmap_get_string(const __StringHashmap* map, const void* key){
    uint64_t hash = __hash_str(key) % map->max_items;
    uint64_t start_hash = hash;
    void* value = NULL;
    while(map->items[hash] != NULL) {
        if(strcmp(*(char**)map->items[hash], key) == 0) {
            value = (char*)map->items[hash] + sizeof(char*);
            break;
        }

        hash++;

        hash %= map->max_items;

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

bool __hashmap_remove_string(__StringHashmap* map, const void* key) {
    uint64_t hash = __hash_str(key) % map->max_items;
    uint64_t start_hash = hash;
    while(map->items[hash] != NULL) {
        if(strcmp(*(char**)map->items[hash], key) == 0) {
            free(*(char**)map->items[hash]);
            free(map->items[hash]);
            map->items[hash] = NULL;
            map->item_count--;
            return true;
        }

        hash++;

        hash %= map->max_items;

        if(hash == start_hash)
            break;
    }

    return false;
}

char** __hashmap_keys_string(const __StringHashmap* map){
    char** keys = malloc(map->item_count * sizeof(char*));
    uint32_t item_index = 0;
    for(uint32_t i = 0; item_index <  map->item_count; i++) {
        if(map->items[i] == NULL)
            continue;
        keys[item_index] = *(char**)map->items[i];
        item_index++;
    }

    return keys;
}

bool __hashmap_has_key_string(const __StringHashmap* map, const void* key){
    uint64_t hash = __hash_str(key) % map->item_count;
    uint64_t start_hash = hash;
    while(map->items[hash] != NULL) {
        if(strcmp(*(char**)map->items[hash], key) == 0)
            return true;

        hash++;

        hash %= map->max_items;

        if(hash == start_hash)
            break;
    }

    return false;
}

void __hashmap_free_string(__StringHashmap* map) {
    for(uint32_t i = 0; i < map->max_items; i++) {
        if(map->items[i] != NULL) {
            free(*(char**)map->items[i]);
            free(map->items[i]);
        }
    }
    free(map->items);
    free(map);
}

/* ----------------- GENERIC HASHMAP FUNCTIONS (voodoo stuff) ----------------- */
void __hashmap_resize(Hashmap* p_map, uint32_t new_size, __p_hash_function hash_function) {
#ifdef HASHMAP_DEBUG
    printf("Attempting to resize the Hashmap at 0x%p to the size %u", map, new_size);
#endif

    struct Map { 
        void** items;
        uint64_t item_count;
        uint64_t max_items;
    };

    struct Map* map = (struct Map*)p_map; 

    uint32_t old_size = map->max_items;
    void** new_items = malloc(sizeof(void*) * new_size);

    memset(new_items, 0, sizeof(void*) * new_size);
    for(uint32_t i = 0; i < old_size; i++){
        if(map->items[i] == NULL)
            continue;

        uint64_t hash = hash_function(map->items[i]) % new_size;
        while(new_items[hash] != NULL) { 
            hash++; 
            hash %= new_size; 
        }
        new_items[hash] = map->items[i];
    }

    free(map->items);

    map->items = new_items;
    map->max_items = new_size;

}

uint64_t hashmap_count(const Hashmap* map) {
    return *(uint64_t*)((char*)map + sizeof(void**));
}

void hashmap_foreach(Hashmap* map, cbfp_t callback) {
#ifdef HASHMAP_DEBUG
    printf("hashmap_foreach: map - 0x%p | item_count - %u | callback - 0x%p\n", map->items, map->item_count, callback);
#endif
    uint64_t item_count = hashmap_count(map);
    uint64_t item_index = 0;
    void** items = *(void***)(map);
    for(uint32_t i = 0; item_index <  item_count; i++) {
        if(items[i] == NULL)
            continue;
        callback(items[i]);
        item_index++;
    }
}