/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdint.h>
#include <stdbool.h>

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <libgen.h>
#include <assert.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/x509.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <user_ta_header_defines.h>
#include <types.h>

static uint32_t curve_openssl_to_tee(int openssl_id) {
    // P-256
    #define NID_X9_62_prime256v1 415
    #define TEE_ECC_CURVE_NIST_P256 0x00000003
    // P-384
    #define NID_secp384r1 715
    #define TEE_ECC_CURVE_NIST_P384 0x00000004
    // P-521
    #define NID_secp521r1 716
    #define TEE_ECC_CURVE_NIST_P521 0x00000005

    return
        (openssl_id==NID_X9_62_prime256v1)?TEE_ECC_CURVE_NIST_P256:
        (openssl_id==NID_secp384r1)?TEE_ECC_CURVE_NIST_P384:
        (openssl_id==NID_secp521r1)?TEE_ECC_CURVE_NIST_P521:0;
}

// kp_bncpy():
// * buf : either destination buffer or NULL. If NULL buffer is initialized
static void kp_bncpy(struct keybuf_t *b, const BIGNUM *bn) {
    b->sz = BN_num_bytes(bn);
    // Ensure field is not empty
    assert(b->sz);
    // Ensure allocation hasn't failed
    (void)BN_bn2bin(bn, &b->b[0]);
}

void kp_clean(struct keypair_t *kp) {
    if(kp->type == KEYTYPE_RSA) {
        memset(&kp->u.rsa, 0, sizeof(struct RSA_t));
    } else {
        memset(&kp->u.ecc, 0, sizeof(struct ECC_t));
    }
}

// digest_public_key: calculates the SHA256 digest of the
// hexadecimal representation of the EVP public key. For an RSA key
// this is based on public modulus. For an EC key, this is based on
// the key's elliptic curve group and public key point.
// Digest must be initialized with at least 32 bytes of space and is used to
// return the SHA256 digest.
static bool digest_public_key(struct keypair_t *key, uint8_t *digest) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(ctx, EVP_sha256(), 0);
    if (key->type == KEYTYPE_RSA) {
        EVP_DigestUpdate(ctx, key->u.rsa.n.b, key->u.rsa.n.sz);
    } else {
        EVP_DigestUpdate(ctx, (void*)&key->u.ecc.curve_id, sizeof(key->u.ecc.curve_id));
        EVP_DigestUpdate(ctx, key->u.ecc.x.b, key->u.ecc.x.sz);
        EVP_DigestUpdate(ctx, key->u.ecc.y.b, key->u.ecc.y.sz);
    }
    EVP_DigestFinal_ex(ctx, digest, 0);
    EVP_MD_CTX_destroy(ctx);
    return true;
}

static bool get_keypair(EVP_PKEY *key, struct keypair_t *keypair) {
    switch (key->type) {
    case EVP_PKEY_RSA: {
        keypair->type = KEYTYPE_RSA;
        RSA *rsa = EVP_PKEY_get1_RSA(key);
        if (!rsa) {
            errx(1, "Can't read RSA key");
            return false;
        }
        kp_bncpy(&keypair->u.rsa.n, rsa->n);
        kp_bncpy(&keypair->u.rsa.d, rsa->d);
        kp_bncpy(&keypair->u.rsa.e, rsa->e);
        kp_bncpy(&keypair->u.rsa.p, rsa->p);
        kp_bncpy(&keypair->u.rsa.q, rsa->q);
        kp_bncpy(&keypair->u.rsa.dp, rsa->dmp1);
        kp_bncpy(&keypair->u.rsa.dq, rsa->dmq1);
        kp_bncpy(&keypair->u.rsa.qinv, rsa->iqmp);

        printf("RSA Key Size: %lu\n", keypair->u.rsa.n.sz*8);
        break;
    }
    case EVP_PKEY_EC: {
        EC_KEY *ec_key;
        const EC_POINT *ec_pub_key;
        const EC_GROUP *group;
        BIGNUM *x, *y;

        keypair->type = KEYTYPE_ECC;
        BN_CTX *ctx = BN_CTX_new();
        if (!ctx) return false;

        // Get curve
        ec_key = EVP_PKEY_get1_EC_KEY(key);
        if (!ec_key) return false;

        ec_pub_key = EC_KEY_get0_public_key(ec_key);
        if (!ec_pub_key) return false;

        group = EC_KEY_get0_group(ec_key);
        if (!group) return false;

        // Get private key
        const BIGNUM *bn = EC_KEY_get0_private_key(ec_key);
        kp_bncpy(&keypair->u.ecc.scalar, bn);

        // Get public key
        keypair->u.ecc.curve_id
            = curve_openssl_to_tee(EC_GROUP_get_curve_name(group));

        x = BN_new(); y = BN_new();
        if (!x || !y) return false;

        if (!EC_POINT_get_affine_coordinates_GFp(group, ec_pub_key, x, y, ctx)) {
            BN_free(x); BN_free(y);
            return false;
        }
        kp_bncpy(&keypair->u.ecc.x, x);
        kp_bncpy(&keypair->u.ecc.y, y);
        OPENSSL_free(ctx);
        BN_free(x); BN_free(y); // OMG, refactoring is necessairy

        break;
    }
    default:
        errx(1, "Unsupported key type");
        return false;
    }

    return true;
}

// parse_key_from_file: adds a private key from a file location, returns
// TZKSSL_ERROR_NONE if successful, or a TZKSSL_ERROR_* if a problem
// occurs. Adds the private key to the list if successful.
static tzkssl_error_code parse_key_from_file(
    const char *path,
    struct keypair_t *kp) {

    uint8_t pubkey_hash[SHA256_SIZE];
    BIO *bp;
    EVP_PKEY *key;
    tzkssl_error_code err = TZKSSL_ERROR_NONE;

    bp = BIO_new(BIO_s_file());
    if (!bp) {
        err = TZKSSL_ERROR_INTERNAL;
        goto end;
    }

    if (!BIO_read_filename(bp, path)) {
        errx(1, "Failed to open private key file %s", path);
        err = TZKSSL_ERROR_INTERNAL;
        goto end;
    }

    key = PEM_read_bio_PrivateKey(bp, 0, 0, 0);
    if (!key) {
        err = TZKSSL_ERROR_INTERNAL;
        goto end;
    }

    if (!get_keypair(key, kp)) {
        err = TZKSSL_ERROR_INTERNAL;
        goto end;
    }

    if (!digest_public_key(kp, pubkey_hash)) {
        err = TZKSSL_ERROR_INTERNAL;
        goto end;
    }

end:
    BIO_free(bp);
    return err;
}

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_UUID;
	uint32_t err_origin;
    uint32_t cmd;
    struct keypair_t kp = {0};

    uint8_t msg[] = "The quick brown fox jumps over the lazy dog word";
    uint8_t sign[512] = {0};

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/*
	 * Open a session to the "hello world" TA, the TA will print "hello
	 * world!" in the log when the session is created.
	 */
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	/*
	 * Execute a function in the TA by invoking it, in this case
	 * we're incrementing a number.
	 *
	 * The value of command ID part and how the parameters are
	 * interpreted is part of the interface provided by the TA.
	 */

	/* Clear the TEEC_Operation struct */
	memset(&op, 0, sizeof(op));

	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */

	/*
	 * TA_INSTALL_KEYS is the actual function in the TA to be
	 * called.
	 */
    if (argc < 2) {
        printf("E: Argc must be 2\n");
    }

    if (parse_key_from_file(argv[3], &kp) != TZKSSL_ERROR_NONE) {
        errx(1, "parse_key_from_file() failed");
    }

    uint8_t sni_sha256[32];
    if (!EVP_Digest(argv[2], strlen(argv[2]), sni_sha256, NULL, EVP_sha256(), NULL)) {
        errx(1, "EVP_Digest");
    }

    if (!strncmp(argv[1], "put", 3)) {
        cmd = TA_INSTALL_KEYS;
        if (argc != 4) {
            printf("Filename missing\n");
        }
        op.paramTypes = TEEC_PARAM_TYPES(
                        TEEC_MEMREF_TEMP_INPUT,
                        TEEC_MEMREF_TEMP_INPUT,
                        TEEC_NONE,
                        TEEC_NONE);
        op.params[0].tmpref.buffer = (void*) &kp;
        op.params[0].tmpref.size = sizeof(kp);
        op.params[1].tmpref.buffer = sni_sha256;
        op.params[1].tmpref.size = 32;
    } else if (!strncmp(argv[1], "has", 3)) {
        cmd = TA_HAS_KEYS;
        op.paramTypes = TEEC_PARAM_TYPES(
                        TEEC_MEMREF_TEMP_INPUT,
                        TEEC_NONE,
                        TEEC_NONE,
                        TEEC_NONE);
        op.params[0].tmpref.buffer = sni_sha256;
        op.params[0].tmpref.size = 32;
    } else if (!strncmp(argv[1], "del", 3)) {
        cmd = TA_DEL_KEYS;
        op.paramTypes = TEEC_PARAM_TYPES(
                        TEEC_MEMREF_TEMP_INPUT,
                        TEEC_NONE,
                        TEEC_NONE,
                        TEEC_NONE);
        op.params[0].tmpref.buffer = sni_sha256;
        op.params[0].tmpref.size = 32;
    } else {
        errx(1, "E: Command must be 'put filename' or 'has' or 'del'");
    }

	res = TEEC_InvokeCommand(&sess, cmd, &op, &err_origin);
    if (!strncmp(argv[1], "has", 3)) {
        printf("Key %sfound\n", res==TEEC_SUCCESS?"":"not ");
    } else {
        if (res != TEEC_SUCCESS) {
            errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
                res, err_origin);
        }
    }

	/*
	 * We're done with the TA, close the session and
	 * destroy the context.
	 *
	 * The TA will print "Goodbye!" in the log when the
	 * session is closed.
	 */

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	return 0;
}
