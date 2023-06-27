// gcc -o bagoftricks bagoftricks.c -fno-stack-protector -no-pie
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]){
    char fmt[32];
    read(0, fmt, 400);

    return 0;
}