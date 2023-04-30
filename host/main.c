#include <err.h>
#include <stdio.h>
#include <string.h>

#include <tee_client_api.h>

#include <TEEencrypt_ta.h>

#define RSA_KEY_SIZE 1024
#define RSA_MAX_PLAIN_LEN_1024 86
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char rsa_plain_text[RSA_MAX_PLAIN_LEN_1024] = {0,};
	char rsa_cipher_text[RSA_CIPHER_LEN_1024] = {0,};
	char plain_text[1024] = {0,};
	char cipher_text[1024] = {0,};
	char encrypted_key[3];
	int len = 1024;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);

	memset(&op, 0, sizeof(op));
	
	if(argc != 4){
		printf("[Error] Check your command.");
	}
	else if(strcmp(argv[3], "Caesar") == 0){
		printf("\nAlgorithm : Caesar\n");
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE);
		if(strcmp(argv[1], "-e") == 0){
			FILE* fpr = fopen(argv[2], "r");
                	fread(plain_text, sizeof(plain_text), 1, fpr);
                	fclose(fpr);

			op.params[0].tmpref.buffer = plain_text;
                	op.params[0].tmpref.size = len;

			printf("\n======================= Caesar Encryption =======================\n");
	                printf("Plaintext : %s\n", plain_text);

			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_GET, &op, &err_origin);
	                res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &err_origin);
	                res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_ENC, &op, &err_origin);
			memcpy(cipher_text, op.params[0].tmpref.buffer, len);
			printf("Ciphertext : %s", cipher_text);

			encrypted_key[0] = op.params[1].value.a;
	                encrypted_key[1] = '\0';
	                strcat(cipher_text, encrypted_key);

			FILE* fpw = fopen("./ciphertext.txt", "w");
	                fwrite(cipher_text, strlen(cipher_text), 1, fpw);
	                fclose(fpw);
		}
		else if(strcmp(argv[1], "-d") == 0){
			FILE* fpr = fopen(argv[2], "r");
                	fread(cipher_text, sizeof(cipher_text), 1, fpr);
                	fclose(fpr);

			op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE);
	                op.params[0].tmpref.buffer = cipher_text;
	                op.params[0].tmpref.size = len;
			
			printf("\n======================= Caesar Decryption =======================\n");
			printf("Ciphertext : %s\n", cipher_text);

			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_DEC, &op, &err_origin);
	                res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op, &err_origin);
			memcpy(plain_text, op.params[0].tmpref.buffer, len);
			printf("Plaintext : %s\n", plain_text);

			FILE* fpw = fopen("./plaintext.txt", "w");
	                fwrite(plain_text, strlen(plain_text), 1, fpw);
	                fclose(fpw);
		}
	}
	else if(strcmp(argv[3], "RSA") == 0 && strcmp(argv[1], "-e") == 0){
		printf("\nAlgorithm : RSA\n");

		FILE* fpr = fopen(argv[2], "r");
                fread(rsa_plain_text, sizeof(rsa_plain_text), 1, fpr);
                fclose(fpr);

		op.params[0].tmpref.buffer = rsa_plain_text;
                op.params[0].tmpref.size = RSA_MAX_PLAIN_LEN_1024;
                op.params[1].tmpref.buffer = rsa_cipher_text;
                op.params[1].tmpref.size = RSA_CIPHER_LEN_1024;

		printf("\n========================= RSA Encryption ========================\n");
		printf("Plaintext : %s\n", rsa_plain_text);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_RSA_CMD_GENKEYS, NULL, NULL);
		printf("\n===================== Keys already generated ====================\n");
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_RSA_CMD_ENCRYPT, &op, &err_origin);
		memset(rsa_cipher_text, op.params[1].tmpref.buffer, RSA_CIPHER_LEN_1024);
		printf("\nThe text send was encrypted : %s\n", rsa_cipher_text);

		FILE* fpw = fopen("./ciphertext.txt", "w");
                fwrite(rsa_cipher_text, strlen(rsa_cipher_text), 1, fpw);
		fclose(fpw);
	}
	else{
		printf("[Error] Encryption cannot proceed.\n");
	}

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
