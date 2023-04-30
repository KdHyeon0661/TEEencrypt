#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <TEEencrypt_ta.h>
#define RSA_KEY_SIZE 1024
#define MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

int root_key;
int random_key;

struct rsa_session{
	TEE_OperationHandle op_handle;
	TEE_ObjectHandle key_handle;
};

TEE_Result prepare_rsa_operation(TEE_OperationHandle *handle, uint32_t alg, TEE_OperationMode mode, TEE_ObjectHandle key){
	TEE_Result ret = TEE_SUCCESS;	
	TEE_ObjectInfo key_info;
	ret = TEE_GetObjectInfo1(key, &key_info);
	if (ret != TEE_SUCCESS) {
		EMSG("\nTEE_GetObjectInfo1: %#\n" PRIx32, ret);
		return ret;
	}

	ret = TEE_AllocateOperation(handle, alg, mode, key_info.keySize);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to alloc operation handle : 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Operation allocated successfully. ==========\n");

	ret = TEE_SetOperationKey(*handle, key);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to set key : 0x%x\n", ret);
		return ret;
	}
    	DMSG("\n========== Operation key already set. ==========\n");

	return ret;
}

TEE_Result check_params(uint32_t param_types){
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void){
	DMSG("TA_CreateEntryPoint has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void){
	DMSG("TA_DestroyEntryPoint has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx){
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("TA_OpenSessionEntryPoint has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	IMSG("Hello World!\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx){
	(void)&sess_ctx; /* Unused parameter */
	IMSG("Goodbye!\n");
}

static TEE_Result randomkey_get(uint32_t param_types, TEE_Param params[4]){
        DMSG("========================Get RandomKey========================\n");
        do{
                TEE_GenerateRandom(&random_key, sizeof(random_key));
                random_key = random_key % 26;
        }while(random_key == 0);

	if(random_key < 0){
		random_key *= -1;
	}

        DMSG("Random Key: %d\n", random_key);
        return TEE_SUCCESS;
}

static TEE_Result enc_value(uint32_t param_types, TEE_Param params[4]){
	char * in = (char *)params[0].memref.buffer;
	int in_len = strlen(params[0].memref.buffer);
	char encrypted[1024] = {0,};

	DMSG("======================= Encryption =======================\n");
	DMSG("Plaintext: %s", in);
	memcpy(encrypted, in, in_len);

	for(int i=0; i<in_len; i++){
		if(encrypted[i] >= 'a' && encrypted[i] <= 'z'){
			encrypted[i] = (encrypted[i] - 'a' + random_key) % 26 + 'a';
		}
		else if(encrypted[i] >= 'A' && encrypted[i] <= 'Z'){
			encrypted[i] = (encrypted[i] - 'A' + random_key) % 26 + 'A';
		}
	}
	DMSG("Ciphertext: %s", encrypted);
	memcpy(in, encrypted, in_len);

	return TEE_SUCCESS;
}

static TEE_Result randomkey_enc(uint32_t param_types, TEE_Param params[4]){

	DMSG("======================= RandomKey Encryption =======================\n");

	if(random_key >= 'a' && random_key <= 'z'){
		random_key = (random_key - 'a' + root_key) % 26 + 'a';
	}
	else if(random_key >= 'A' && random_key <= 'Z'){
		random_key = (random_key - 'A' + root_key) % 26 + 'A';
	}
	params[1].value.a = (uint32_t)random_key;
	return TEE_SUCCESS;
}

static TEE_Result randomkey_dec(uint32_t param_types, TEE_Param params[4])
{
	char * in = (char *)params[0].memref.buffer;
	int in_len = strlen(params[0].memref.buffer);
	char encrypted[1024] = {0,};

	DMSG("======================= RandomKey Decryption =======================\n");
	memcpy(encrypted, in, in_len);

	// Get Random Key
	random_key = encrypted[in_len-1];
	DMSG("Random Key: %d\n", random_key);

	if(random_key >= 'a' && random_key <= 'z'){
		random_key = (random_key - 'a' - root_key + 26) % 26 + 'a';
	}
	else if(random_key >= 'A' && random_key <= 'Z'){
		random_key = (random_key - 'A' - root_key + 26) % 26 + 'A';
	}
	DMSG("Got Value: %c\n", encrypted[in_len-1]);
	DMSG("Decrypted: %d\n", random_key);
	return TEE_SUCCESS;
}

static TEE_Result dec_value(uint32_t param_types, TEE_Param params[4])
{
        char * in = (char *)params[0].memref.buffer;
        int in_len = strlen(params[0].memref.buffer);
        char decrypted[1024] = {0,};

        DMSG("======================= Decryption =======================\n");
        DMSG ("Ciphertext:  %s", in);
        memcpy(decrypted, in, in_len);

        for(int i=0; i<in_len-1;i++){
                if(decrypted[i]>='a' && decrypted[i] <='z'){
                        decrypted[i] = (decrypted[i] - 'a' - random_key + 26) % 26 + 'a';
                }
                else if (decrypted[i] >= 'A' && decrypted[i] <= 'Z') {
                        decrypted[i] = (decrypted[i] - 'A' - random_key + 26) % 26 + 'A';
                }
        }
	decrypted[in_len-1] = '\0';
        DMSG ("Plaintext : %s", decrypted);
        memcpy(in, decrypted, in_len);

        return TEE_SUCCESS;
}

TEE_Result RSA_create_key_pair(void *sess_ctx){
	TEE_Result ret;
	size_t key_size = RSA_KEY_SIZE;
	struct rsa_session *sess = (struct rsa_session *)sess_ctx;
	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &sess->key_handle);

	DMSG("\n========== Transient object allocated ==========\n");

	ret = TEE_GenerateKey(sess->key_handle, key_size, (TEE_Attribute *)NULL, 0);

	DMSG("\n========== Keys generated ==========\n");
	return ret;
}

TEE_Result RSA_encrypt(void *sess_ctx, uint32_t param_types, TEE_Param params[4]){
	TEE_Result ret;
	uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5;
	struct rsa_session *sess = (struct rsa_session *)sess_ctx;
	DMSG("\n========== T1 ==========\n");
	if(check_params(param_types) != TEE_SUCCESS){
		DMSG("\n\nBAD_PARAMETERS\n\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	DMSG("\n========== T2 ==========\n");
	void *plain_txt = params[0].memref.buffer;
	size_t plain_len = params[0].memref.size;
	void *cipher = params[1].memref.buffer;
	size_t cipher_len = params[1].memref.size;

	DMSG("\n========== Preparing encryption operation ==========\n");
	ret = prepare_rsa_operation(&sess->op_handle, rsa_alg, TEE_MODE_ENCRYPT, sess->key_handle);

	DMSG("\nData to encrypt: %s\n", (char*) plain_txt);
	ret = TEE_AsymmetricEncrypt(sess->op_handle, (TEE_Attribute *)NULL, 0, plain_txt,
					plain_len, cipher, &cipher_len);

	DMSG("\nEncrypted data: %s\n", (char *) cipher);
	DMSG("\n========== Encryption successfully =========\n");
	return ret;

	err:
	TEE_FreeOperation(sess->op_handle);
	TEE_FreeOperation(sess->key_handle);
	return ret;
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
	root_key = 13;

	switch (cmd_id) {
	case TA_TEEencrypt_CMD_ENC_VALUE:
		return enc_value(param_types, params);
	case TA_TEEencrypt_CMD_DEC_VALUE:
		return dec_value(param_types, params);
	case TA_TEEencrypt_CMD_RANDOMKEY_GET:
		return randomkey_get(param_types, params);
	case TA_TEEencrypt_CMD_RANDOMKEY_ENC:
		return randomkey_enc(param_types, params);
	case TA_TEEencrypt_CMD_RANDOMKEY_DEC:
		return randomkey_dec(param_types, params);
	case TA_TEEencrypt_RSA_CMD_GENKEYS:
		return RSA_create_key_pair(sess_ctx);
	case TA_TEEencrypt_RSA_CMD_ENCRYPT:
		return RSA_encrypt(sess_ctx, param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
