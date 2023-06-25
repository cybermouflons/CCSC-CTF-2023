// gcc -o babyrop babyrop.c -static-pie
#include <stdio.h>
#include <stdlib.h>

void setup(){
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    fflush(stdout);
}

int main(int argc, char* argv[]){
    char buf[64];
    char fmt[32];

    setup();

    read(0, fmt, 31);
    fmt[31] = '\0';
    printf(fmt);

    read(0, buf, 200);
    return 0;
}