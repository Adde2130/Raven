#include <stdio.h>

int main(){
#ifdef __GNUC__
    printf("WORKS");
    #endif
}