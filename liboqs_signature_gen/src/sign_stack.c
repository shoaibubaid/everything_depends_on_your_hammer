/*
 * example_sphincsplus.c
 *
 * Minimal example of using SPHINCS+-SHA2-256f from liboqs.
 *
 * SPDX-License-Identifier: MIT
 */

 #include <stdbool.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 
 #include <oqs/oqs.h>

 #include "fprintbstr.h"
 
 #define MESSAGE_LEN 50
 #define EXT_DATA_ERROR -1
 
 void cleanup_stack(uint8_t *secret_key, size_t secret_key_len);

 
 static OQS_STATUS example_stack(void) {
 
 #ifdef OQS_ENABLE_SIG_sphincs_sha2_256f_simple_avx2
 
     OQS_STATUS rc;
     FILE *fp_rsp = fopen("signature.txt", "w");
     FILE *fp_pub = fopen("key.txt", "r");
     
     uint8_t public_key[OQS_SIG_sphincs_sha2_256f_simple_length_public_key];
     uint8_t secret_key[OQS_SIG_sphincs_sha2_256f_simple_length_secret_key];
     uint8_t message[MESSAGE_LEN];
     uint8_t signature[OQS_SIG_sphincs_sha2_256f_simple_length_signature];
     size_t message_len = MESSAGE_LEN;
     size_t signature_len;
 
     OQS_randombytes(message, message_len);

    if (!ReadHex(fp_pub, secret_key, OQS_SIG_sphincs_sha2_256f_simple_length_secret_key, "sk = "))
    {
        printf("ERROR: unable to read 'sk' from <%s>\n", "fn_req");
        return EXT_DATA_ERROR;
    }

    if (!ReadHex(fp_pub, public_key, OQS_SIG_sphincs_sha2_256f_simple_length_public_key, "pk = "))
    {
        printf("ERROR: unable to read 'pk' from <%s>\n", "fn_req");
        return EXT_DATA_ERROR;
    }
    
     rc = OQS_SIG_sphincs_sha2_256f_simple_sign(signature, &signature_len, message, message_len, secret_key);
     if (rc != OQS_SUCCESS) {
         printf("crypto_sign_open returned <-1>\n");
         cleanup_stack(secret_key, OQS_SIG_sphincs_sha2_256f_simple_length_secret_key);
         return OQS_ERROR;
     }


     fprintf(fp_rsp, "mlen = %d\n", MESSAGE_LEN);
     fprintbstr(fp_rsp, "msg = ", message, MESSAGE_LEN);
     fprintbstr(fp_rsp, "signature = ", signature, OQS_SIG_sphincs_sha2_256f_simple_length_signature);
 
    //  rc = OQS_SIG_sphincs_sha2_256f_simple_verify(message, message_len, signature, signature_len, public_key);
    //  if (rc != OQS_SUCCESS) {
    //      printf("crypto_sign_open returned <-1>\n");
    //      cleanup_stack(secret_key, OQS_SIG_sphincs_sha2_256f_simple_length_secret_key);
    //      return OQS_ERROR;
    //  }
 
     printf("signature for OQS_SIG_sphincs_sha2_256f_simple generated and stored in signature.txt.\n");
     cleanup_stack(secret_key, OQS_SIG_sphincs_sha2_256f_simple_length_secret_key);
     return OQS_SUCCESS;
 
 #else
 
     printf("[example_stack] OQS_SIG_sphincs_sha2_256f_simple was not enabled at compile-time.\n");
     return OQS_SUCCESS;
 
 #endif
 }
 
 int main(void) {
     OQS_init();
     if (example_stack() == OQS_SUCCESS){
         OQS_destroy();
         return EXIT_SUCCESS;
     } else {
         OQS_destroy();
         return EXIT_FAILURE;
     }
 }
 
 void cleanup_stack(uint8_t *secret_key, size_t secret_key_len) {
     OQS_MEM_cleanse(secret_key, secret_key_len);
 }

 