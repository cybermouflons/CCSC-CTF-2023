
#include "aes.h"

int main() {
    uint8_t input[] = {"testcifratura123"};
    uint8_t key[16] = {0x70, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64, 0x70 , 0x61 , 0x73 , 0x73 , 0x77 , 0x6F , 0x72 , 0x64};
    
    AES128_ECB_indp_setkey(key);

    AES128_ECB_indp_crypto(input);

    return 0;
}