#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>
#define MOVBSIGN(x) (-((x) >> 31))
#define MAX_RSA_KEY_SIZE 512
#define SHA1_SIZE   20    // SHA-1   output size
#define SHA256_SIZE 32    // SHA-256 output size

struct buf_t {
    uint8_t *b;
    size_t sz;
};

struct keybuf_t {
    uint8_t b[MAX_RSA_KEY_SIZE];
    size_t sz;
};

typedef enum {
    TZKSSL_ERROR_NONE              = 0x00,
    TZKSSL_ERROR_CRYPTO_FAILED     = 0x01,
    TZKSSL_ERROR_KEY_NOT_FOUND     = 0x02,
    TZKSSL_ERROR_READ              = 0x03,
    TZKSSL_ERROR_VERSION_MISMATCH  = 0x04,
    TZKSSL_ERROR_BAD_OPCODE        = 0x05,
    TZKSSL_ERROR_UNEXPECTED_OPCODE = 0x06,
    TZKSSL_ERROR_FORMAT            = 0x07,
    TZKSSL_ERROR_INTERNAL          = 0x08
} tzkssl_error_code;

typedef enum {
    KEYTYPE_RSA = 0,
    KEYTYPE_ECC = 1
} keytype_t;

struct keypair_t {
    keytype_t type;
    union {
        struct RSA_t {
            size_t key_byte_size;
            struct keybuf_t n;
            struct keybuf_t p;
            struct keybuf_t q;
            struct keybuf_t e;
            struct keybuf_t d;
            struct keybuf_t dp;
            struct keybuf_t dq;
            struct keybuf_t qinv;
        } rsa;
        struct ECC_t {
            uint32_t curve_id;
            struct keybuf_t scalar;
            struct keybuf_t x;
            struct keybuf_t y;
        } ecc;
    } u;
};

#endif // TYPES_H