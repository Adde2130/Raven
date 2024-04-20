#include "raven_util.h"

char* wstr_to_str(LPCWSTR str) {
    int size = WideCharToMultiByte(CP_UTF8, 0, str, -1, NULL, 0, NULL, NULL);
    char* result = (char*)malloc(size * sizeof(char));
    WideCharToMultiByte(CP_UTF8, 0, str, -1, result, size, NULL, NULL);
    return result;
}

void patch_linked_list(LIST_ENTRY* list, bool protected_memory) {
    if(!list)
        return;

    if(protected_memory) {
        if(list->Blink)
            protected_write(&list->Blink->Flink, &list->Flink, sizeof(LIST_ENTRY*));
        if(list->Flink)
            protected_write(&list->Flink->Blink, &list->Blink, sizeof(LIST_ENTRY*));
    } else {
        if(list->Blink)
            list->Blink->Flink = list->Flink;
        if(list->Flink)
            list->Flink->Blink = list->Blink; 
    }
}