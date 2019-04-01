#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/ecdsa.h>
// OP-TEE
#include <tee_client_api.h>
#include <user_ta_header_defines.h>
#include <types.h>

// Enforce TLS 1.3
#define TLS_PROT_VERSION    TLS1_3_VERSION
#define PORT                           1443
#define IP                             "127.0.0.1"
#define CACERT                         "etc/ca/ca.cert.pem"
#define BUFFER_SIZE                    1024

#define DBG(...)                                                              \
    do {                                                                        \
        (void) fprintf(stdout, "[%s() %s:%d] ", __func__, __FILE__, __LINE__);  \
        (void) fprintf(stdout, __VA_ARGS__);                                    \
        (void) fprintf(stdout, "\n");                                           \
    } while (0)

static const struct CertDesc_t {
    const char* cert;
    const char* cipher;
} Certs = {
    // Location of public key
    .cert = "etc/ecdsa_256.pem",
    // This is the only supported cipher
    .cipher = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
};

static void BSSL_init(void) {
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_library_init();
    CRYPTO_library_init();

    if(!SSL_library_init())
    {
        fprintf(stderr, "** OpenSSL initialization failed!\n");
        exit(-1);
    }
}

static void BSSL_shutdown(void) {

    ERR_free_strings();
    ERR_clear_error();
    CRYPTO_set_locking_callback(NULL);
    CRYPTO_set_id_callback(NULL);
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
}


static int tee_sign_ecdsa(uint8_t *message, uint32_t length,
  uint8_t *out, size_t *size,
  uint8_t key_id[32]) {

  TEEC_Result res;
  TEEC_Context ctx;
  TEEC_Operation op;
  TEEC_Session sess;
  TEEC_UUID uuid = TA_UUID;
  uint32_t err_origin;

  /* Initialize a context connecting us to the TEE */
  res = TEEC_InitializeContext(NULL, &ctx);
  if (res != TEEC_SUCCESS)
    printf("TEEC_InitializeContext failed with code 0x%x", res);

  /*
   * Open a session to the "hello world" TA, the TA will print "hello
   * world!" in the log when the session is created.
   */
  res = TEEC_OpenSession(&ctx, &sess, &uuid,
             TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
  if (res != TEEC_SUCCESS)
    printf("TEEC_Opensession failed with code 0x%x origin 0x%x",
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

  op.paramTypes = TEEC_PARAM_TYPES(
                  TEEC_MEMREF_TEMP_INPUT,
                  TEEC_MEMREF_TEMP_INPUT,
                  TEEC_MEMREF_TEMP_INOUT,
                  TEEC_NONE);
  op.params[0].tmpref.buffer = key_id;
  op.params[0].tmpref.size = 32;
  op.params[1].tmpref.buffer = message;
  op.params[1].tmpref.size = length;
  op.params[2].tmpref.buffer = out;
  op.params[2].tmpref.size = (uint32_t)*size;

  res = TEEC_InvokeCommand(&sess, TA_SIGN_ECC, &op, &err_origin);
  if (res != TEEC_SUCCESS) {
    printf("TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
      res, err_origin);
    return 0;
  }

  TEEC_CloseSession(&sess);
  TEEC_FinalizeContext(&ctx);
  *size = op.params[2].tmpref.size;
  return 1;

}

/*
  Function delegates signing to the TEE. Private keys of the
  server certificate are kept in secure storage accessible
  only from TEE. Keys are index by the hash of server name
  being accessed.

  NOTE on e-SNI: In case of encrypted-SNI (draft-rescorla-tls-esni),
  erver name is decrypted by boringssl before this function is
  called.
*/
enum ssl_private_key_result_t tee_prv_key_sign(
    SSL *ssl, uint8_t *out, size_t *out_len, size_t max_out,
    uint16_t signature_algorithm, const uint8_t *in, size_t in_len) {
    uint8_t digest[32];
    uint8_t sni_sha256[32];
    uint8_t sign[64];
    ECDSA_SIG *ecsig = 0;
    CBB cbb;

    if (max_out < 64+8) {
      printf("max_out to small - should be 72, is %u\n", max_out);
      return ssl_private_key_failure;
    }

    // SNI - used to index certificates
    const char *sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (!EVP_Digest(in, in_len, digest, NULL, EVP_sha256(), 0) ||
        !EVP_Digest(sni, strlen(sni), sni_sha256, NULL, EVP_sha256(), NULL)) {
        printf("E: EVP_Digest\n");
    }

    // Call enclave and sign with private key
    if (!tee_sign_ecdsa(digest, 32, sign, out_len, sni_sha256)) {
        printf("\nERR: tee_sign_ecdsa failed.\n");
        return ssl_private_key_failure;
    }

    // Result from signing must be DER encoded.
    ecsig = ECDSA_SIG_new();
    ecsig->r = BN_bin2bn(sign, 32, ecsig->r);
    ecsig->s = BN_bin2bn(&sign[32], 32, ecsig->s);

    CBB_zero(&cbb);
    if (!CBB_init_fixed(&cbb, out, max_out) ||
        !ECDSA_SIG_marshal(&cbb, ecsig) ||
        !CBB_finish(&cbb, NULL, out_len)) {
      ECDSA_SIG_free(ecsig);
      return ssl_private_key_failure;
    }

    ECDSA_SIG_free(ecsig);
    return ssl_private_key_success;
}

static const SSL_PRIVATE_KEY_METHOD prv_key_method = {
    .sign = tee_prv_key_sign,
    // ECDSA is used, no decryption
    .decrypt = 0,
    // shouldn't be needed,but let see
    .complete = 0
};

static SSL_CTX* setup_server_ctx() {
	SSL_CTX* ctx = SSL_CTX_new(TLS_method());
    assert(ctx);

    const struct CertDesc_t *c = &Certs;

  	if(SSL_CTX_use_certificate_file(ctx, c->cert, SSL_FILETYPE_PEM) != 1)
  		DBG("Error loading certificate from file");

    SSL_CTX_set_private_key_method(ctx, &prv_key_method);

    if (SSL_CTX_set_min_proto_version(ctx, TLS_PROT_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(ctx, TLS_PROT_VERSION) != 1) {
        DBG("Enforcing protocol to TLSv1.2");

    }
    return ctx;
}

// Interface for accepting
int main(int argc, char *argv[])
{
	SSL *ssl;
	SSL_CTX *ctx;
  int ret, fd, client;
  int reuseval = 1;
  struct sockaddr_in a;
  size_t a_len = sizeof(a);

  BSSL_init();
  ctx = setup_server_ctx();

  // configure
  memset(&a, 0, a_len);
  a.sin_family = AF_INET;
  a.sin_port = htons(PORT);
  a.sin_addr.s_addr = INADDR_ANY;

  fd = socket(PF_INET, SOCK_STREAM, 0);
  if (setsockopt(fd,SOL_SOCKET, SO_REUSEADDR, &reuseval, sizeof(reuseval))) {
    DBG("setsockopt");
  }

  if (bind(fd, (struct sockaddr *)&a, sizeof(a))) {
    DBG("bind");
  }

  if (listen(fd, 1)) {
    DBG("listen");
  }

	for(;;) {
		if(!(ssl = SSL_new(ctx)))	{
			DBG("Error creating SSL context");
		}

    // Accept connection
    int fd_accept = accept(fd, (struct sockaddr *)&a, (socklen_t *)&a_len);
    if (fd_accept<0) {
        DBG("accept");
    }
		SSL_set_fd(ssl, fd_accept);

    ret = SSL_accept(ssl);
		if (ret<=0)	{
      ret = SSL_get_error(ssl, ret);
      if (ret == SSL_ERROR_SYSCALL) {
          DBG("Connection closed");
      } else {
          DBG("Critical error occured %d", ret);
          exit(-1);
      }
		}

    SSL_shutdown(ssl);
    SSL_clear(ssl);
	}
  SSL_CTX_free(ctx);

end:
  BSSL_shutdown();
	return 0;
}
