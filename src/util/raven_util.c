#include "raven_util.h"

char* wstr_to_str(LPCWSTR str) {
    int size = WideCharToMultiByte(CP_UTF8, 0, str, -1, NULL, 0, NULL, NULL);
    char* result = (char*)malloc(size * sizeof(char));
    WideCharToMultiByte(CP_UTF8, 0, str, -1, result, size, NULL, NULL);
    return result;
}