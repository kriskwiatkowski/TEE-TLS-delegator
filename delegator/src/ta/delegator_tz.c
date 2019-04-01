#include <stdio.h>
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <delegator_tz.h>
#include <types.h>

#ifdef ATTR_REF
#undef ATTR_REF
#endif
#define ATTR_REF(CNT, ATTR, BUF) \
	TEE_InitRefAttribute(&attrs[(CNT)++], (ATTR), (BUF).b, (BUF).sz)

#define LOG_RET(ret) 						\
	if((ret)!=TEE_SUCCESS) { 				\
		EMSG("ERR: %d %X", __LINE__, ret); 	\
		return ret; 						\
	}

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	EMSG("Goodbye!\n");
}

// Creates new RSA key
static TEE_ObjectHandle create_rsa_key(struct keypair_t *kp) {
	TEE_Result res;
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	TEE_Attribute attrs[8];
	struct RSA_t *rsa;
	size_t cnt = 0;

 	rsa = &kp->u.rsa;
	res = TEE_AllocateTransientObject(
		TEE_TYPE_RSA_KEYPAIR,
		rsa->n.sz * 8,
		&obj);

	if (res != TEE_SUCCESS) {
		EMSG("E: TEE_AllocateTransientObject failed");
		goto err;
	}

	ATTR_REF(cnt, TEE_ATTR_RSA_MODULUS, rsa->n);
	ATTR_REF(cnt, TEE_ATTR_RSA_PUBLIC_EXPONENT, rsa->e);
	ATTR_REF(cnt, TEE_ATTR_RSA_PRIVATE_EXPONENT, rsa->d);
	// OZAPTF: CRT?

	res = TEE_PopulateTransientObject(obj, attrs, cnt);
	if (res != TEE_SUCCESS) {
		EMSG("E: TEE_PopulateTransientObject failed");
		goto err;
	}
	return obj;

err:
	TEE_FreeTransientObject(obj);
	return TEE_HANDLE_NULL;
}

// Creates new ECC key
static TEE_ObjectHandle create_ecc_key(struct keypair_t *kp) {
	TEE_Result res;
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	TEE_Attribute attrs[4];
	struct ECC_t *ecc;
	size_t cnt = 0;

 	ecc = &kp->u.ecc;
	res = TEE_AllocateTransientObject(
		TEE_TYPE_ECDSA_KEYPAIR,
		ecc->x.sz * 8,
		&obj);

	if (res != TEE_SUCCESS) {
		EMSG("E: TEE_AllocateTransientObject failed");
		goto err;
	}

	ATTR_REF(cnt, TEE_ATTR_ECC_PRIVATE_VALUE, ecc->scalar);
	ATTR_REF(cnt, TEE_ATTR_ECC_PUBLIC_VALUE_X, ecc->x);
	ATTR_REF(cnt, TEE_ATTR_ECC_PUBLIC_VALUE_Y, ecc->y);
	TEE_InitValueAttribute(&attrs[cnt++], TEE_ATTR_ECC_CURVE,ecc->curve_id, 0);
	res = TEE_PopulateTransientObject(obj, attrs, cnt);
	if (res != TEE_SUCCESS) {
		EMSG("E: TEE_PopulateTransientObject failed");
		goto err;
	}
	return obj;

err:
	TEE_FreeTransientObject(obj);
	return TEE_HANDLE_NULL;
}

// Puts the key to the storage
static TEE_Result install_key(uint32_t param_types,
	TEE_Param params[4])
{
	TEE_Result ret;
	TEE_ObjectHandle transient_obj = TEE_HANDLE_NULL;
	TEE_ObjectHandle persistant_obj = TEE_HANDLE_NULL;
	uint32_t exp_param_types;
	struct keypair_t *kp;
	uint8_t fname[SHA256_SIZE];

	EMSG("Storing a key");
	exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	kp = (struct keypair_t*)params[0].memref.buffer;
	if (sizeof(*kp) != params[0].memref.size) {
		EMSG("E: wrong size of keypair_t struct");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	transient_obj =
		(kp->type == KEYTYPE_RSA)
		? create_rsa_key(kp)
		: create_ecc_key(kp);

	if (transient_obj == TEE_HANDLE_NULL) {
		EMSG("E: Can't create transient object");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	// Input TEE_CreatePersistentObject can't be NWd shared buffer
	memcpy(fname, params[1].memref.buffer, params[1].memref.size);
	ret = TEE_CreatePersistentObject(
		TEE_STORAGE_PRIVATE,
		fname, sizeof(fname),
		TEE_DATA_FLAG_ACCESS_WRITE,
		transient_obj,
		NULL/*data*/, 0 /*data_len*/, &persistant_obj);
	if (ret) {
		EMSG("E: Create");
		return ret;
	}
	TEE_FreeTransientObject(transient_obj);
	TEE_CloseObject(persistant_obj);
	return TEE_SUCCESS;
}

// Checks if key exists in the storage
static TEE_Result has_key(uint32_t param_types, TEE_Param params[4]) {
	TEE_Result ret;
	uint32_t c = 0;
	char buf[255] = {0};
	char fname[SHA256_SIZE] = {0};
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	if (params[0].memref.size > sizeof(fname)) {
		EMSG("E: filename too long (>255)");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	memcpy(fname, params[0].memref.buffer, params[0].memref.size);
	ret = TEE_OpenPersistentObject(
		TEE_STORAGE_PRIVATE,
		fname, params[0].memref.size,
		TEE_DATA_FLAG_ACCESS_READ, &obj);

	if (ret) {
		EMSG("E: Open 0x%X", ret);
		return ret;
	}

	ret = TEE_ReadObjectData(obj, buf, sizeof(buf), &c);
	if (ret) {
		EMSG("E: Read");
		return ret;
	}

	TEE_CloseObject(obj);
	return TEE_SUCCESS;
}

// Performs key deletion from the secure storage
static TEE_Result del_key(uint32_t param_types, TEE_Param params[4]) {
	TEE_Result ret;
	char fname[SHA256_SIZE] = {0};
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[0].memref.size > sizeof(fname)) {
		EMSG("E: filename too long (>255)");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	memcpy(fname, params[0].memref.buffer,
		params[0].memref.size);

	ret = TEE_OpenPersistentObject(
		TEE_STORAGE_PRIVATE,
		fname, params[0].memref.size,
		TEE_DATA_FLAG_ACCESS_WRITE_META, &obj);
	if (ret) {
		EMSG("E: Can't open");
		return ret;
	}
	TEE_CloseAndDeletePersistentObject(obj);
	return TEE_SUCCESS;
}

// Performs ECDSA signing with a key from secure storage
static TEE_Result sign_ecdsa(uint32_t param_types, TEE_Param params[4]) {
	TEE_Result ret;
	TEE_OperationHandle op = TEE_HANDLE_NULL;

	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	uint32_t exp_param_types =
		TEE_PARAM_TYPES(
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_INOUT,
			TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[0].memref.size > 32) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	// Must be local
	uint8_t f[32];
	memcpy(f, params[0].memref.buffer, params[0].memref.size);
	ret = TEE_OpenPersistentObject(
		TEE_STORAGE_PRIVATE,
		f, 32,
		TEE_DATA_FLAG_ACCESS_READ, &obj);
	if (ret) {
		EMSG("E: Can't open");
		return ret;
	}

	// perform ECDSA sigining
	ret = TEE_AllocateOperation(&op, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, 256);
	LOG_RET(ret);
	ret = TEE_SetOperationKey(op, obj);
	LOG_RET(ret);
	ret = TEE_AsymmetricSignDigest(op, NULL, 0,
		params[1].memref.buffer, params[1].memref.size,
		params[2].memref.buffer, &params[2].memref.size);
	LOG_RET(ret);

	TEE_CloseObject(obj);
	TEE_FreeOperation(op);
	EMSG("ECDSA signing complated");
	return TEE_SUCCESS;
}

/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */
	switch (cmd_id) {
	case TA_INSTALL_KEYS:
		return install_key(param_types, params);
	case TA_HAS_KEYS:
		return has_key(param_types, params);
	case TA_DEL_KEYS:
		return del_key(param_types, params);
	case TA_SIGN_ECC:
		return sign_ecdsa(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
