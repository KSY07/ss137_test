#include "keygen.h"

uint64_t generate_secure_random_64bit() {
    uint64_t random_number;
    if (RAND_bytes((unsigned char*)&random_number, sizeof(random_number)) != 1) {
        fprintf(stderr, "OpenSSL RAND_bytes failed\n");
        exit(EXIT_FAILURE);
    }
    return random_number;
}

TRIPLE_KEY generateTripleKey() {
    TRIPLE_KEY key = {0U, 0U, 0U};
    
    key[0] = generate_secure_random_64bit();
    key[1] = generate_secure_random_64bit();
    key[2] = generate_secure_random_64bit();
    
    return key;
}