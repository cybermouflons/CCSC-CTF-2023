// gcc -o stack-smashing-2023 stack-smashing-2023.c -no-pie -fno-stack-protector
#include <stdio.h>
#include <stdlib.h>

void setup(){
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    fflush(stdout);
}

int main(int argc, char* argv[]){
    char fmt[32];
    
    setup();

    printf("system@: %p\n", (void*)system);
    
    read(0, fmt, 104);

    return 0;
}