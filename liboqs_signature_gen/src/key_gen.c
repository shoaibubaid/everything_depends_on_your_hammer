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
 
 void cleanup_key(uint8_t *public_key, uint8_t *secret_key,
                   OQS_SIG *sig);
 

 
 static OQS_STATUS example_key(void) {
 
 #ifdef OQS_ENABLE_SIG_sphincs_sha2_256f_simple
 
     OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_sphincs_sha2_256f_simple);
     if (sig == NULL) {
         printf("[example_heap] OQS_SIG_alg_sphincs_sha2_256f_simple was not enabled at compile-time.\n");
         return OQS_ERROR;
     }
 
     uint8_t *public_key = OQS_MEM_malloc(sig->length_public_key);
     uint8_t *secret_key = OQS_MEM_malloc(sig->length_secret_key);
     FILE *fp_key = fopen("key.txt", "w");
     FILE *fp_pub = fopen("collected_pubkey.txt", "w");
     OQS_STATUS rc;
 
     if (!public_key || !secret_key ) {
         fprintf(stderr, "ERROR: OQS_MEM_malloc failed!\n");
         cleanup_key(public_key, secret_key, sig);
         return OQS_ERROR;
     }
 
     rc = OQS_SIG_keypair(sig, public_key, secret_key);
     if (rc != OQS_SUCCESS) {
         fprintf(stderr, "ERROR: OQS_SIG_keypair failed!\n");
         cleanup_key(public_key, secret_key, sig);
         return OQS_ERROR;
     }
 
     
    fprintbstr(fp_key, "sk = ", secret_key, OQS_SIG_sphincs_sha2_256f_simple_length_secret_key);
    fprintbstr(fp_key, "pk = ", public_key, OQS_SIG_sphincs_sha2_256f_simple_length_public_key);
    fprintbstr(fp_pub, "pk = ", public_key, OQS_SIG_sphincs_sha2_256f_simple_length_public_key);
 
     printf("key for OQS_SIG_sphincs_sha2_256f_simple generated successfully and stored in key.txt.\n");
     cleanup_key(public_key, secret_key,sig);
     return OQS_SUCCESS;
 
 #else
 
     printf("[example_heap] OQS_SIG_sphincs_sha2_256f_simple was not enabled at compile-time.\n");
     return OQS_SUCCESS;
 
 #endif
 }
 
 int main(void) {
     OQS_init();
     if (example_key() == OQS_SUCCESS) {
         OQS_destroy();
         return EXIT_SUCCESS;
     } else {
         OQS_destroy();
         return EXIT_FAILURE;
     }
 }
 
 
 void cleanup_key(uint8_t *public_key, uint8_t *secret_key,
                   OQS_SIG *sig) {
     if (sig) {
         OQS_MEM_secure_free(secret_key, sig->length_secret_key);
     }
     OQS_MEM_insecure_free(public_key);
     OQS_SIG_free(sig);
 }
 