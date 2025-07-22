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
 #define TOTAL_SIGNS 1
 
 void cleanup_heap(uint8_t *public_key, uint8_t *secret_key,
                   uint8_t *message, uint8_t *signature,
                   OQS_SIG *sig);
 
 static OQS_STATUS example_heap(void)
 {
 
 #ifdef OQS_ENABLE_SIG_sphincs_sha2_256f_simple
 
     OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_sphincs_sha2_256f_simple);
     if (sig == NULL)
     {
         printf("[example_heap] OQS_SIG_alg_sphincs_sha2_256f_simple was not enabled at compile-time.\n");
         return OQS_ERROR;
     }
 
     uint8_t *public_key = OQS_MEM_malloc(sig->length_public_key);
     uint8_t *secret_key = OQS_MEM_malloc(sig->length_secret_key);
     uint8_t *message = OQS_MEM_malloc(MESSAGE_LEN);
     uint8_t *signature = OQS_MEM_malloc(sig->length_signature);
     size_t message_len = MESSAGE_LEN;
     size_t signature_len;
     FILE *fp_rsp = fopen("signature.txt", "w");
     FILE *fp_pub = fopen("key.txt", "r");
     OQS_STATUS rc;
 
     if (!public_key || !secret_key || !message || !signature)
     {
         fprintf(stderr, "ERROR: OQS_MEM_malloc failed!\n");
         cleanup_heap(public_key, secret_key, message, signature, sig);
         return OQS_ERROR;
     }
 
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
 
    for (int i = 1; i < TOTAL_SIGNS + 1; i++)
    {
         rc = OQS_SIG_sign(sig, signature, &signature_len, message, message_len, secret_key);
         if (rc != OQS_SUCCESS)
         {
             fprintf(stderr, "ERROR: OQS_SIG_sign failed!\n");
             cleanup_heap(public_key, secret_key, message, signature, sig);
             return OQS_ERROR;
         }
         fprintf(fp_rsp, "count = %d\n", i);
         fprintf(fp_rsp, "mlen = %d\n", MESSAGE_LEN);
         fprintbstr(fp_rsp, "msg = ", message, MESSAGE_LEN);
         fprintbstr(fp_rsp, "signature = ", signature, OQS_SIG_sphincs_sha2_256f_simple_length_signature);
 
          rc = OQS_SIG_sphincs_sha2_256f_simple_verify(message, message_len, signature, signature_len, public_key);
          if (rc != OQS_SUCCESS) {
              printf("crypto_sign_open returned <-1>\n");
             //  cleanup_heap(public_key, secret_key,message, signature,sig);
             //  return OQS_ERROR;
          }
     }
 
     //printf("signature for OQS_SIG_sphincs_sha2_256f_simple generated and stored in signature.txt.\n");
     cleanup_heap(public_key, secret_key, message, signature, sig);
     return OQS_SUCCESS;
 
 #else
 
     printf("[example_heap] OQS_SIG_sphincs_sha2_256f_simple was not enabled at compile-time.\n");
     return OQS_SUCCESS;
 
 #endif
 }
 
 int main(void)
 {
     OQS_init();
     if (example_heap() == OQS_SUCCESS)
     {
         OQS_destroy();
         return EXIT_SUCCESS;
     }
     else
     {
         OQS_destroy();
         return EXIT_FAILURE;
     }
 }
 
 void cleanup_heap(uint8_t *public_key, uint8_t *secret_key,
                   uint8_t *message, uint8_t *signature,
                   OQS_SIG *sig)
 {
     if (sig)
     {
         OQS_MEM_secure_free(secret_key, sig->length_secret_key);
     }
     OQS_MEM_insecure_free(public_key);
     OQS_MEM_insecure_free(message);
     OQS_MEM_insecure_free(signature);
     OQS_SIG_free(sig);
 }
 