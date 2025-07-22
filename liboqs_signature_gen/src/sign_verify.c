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
 
 void cleanup_verify(uint8_t *secret_key, size_t secret_key_len);

 
 static OQS_STATUS example_verify(void) {
 
 #ifdef OQS_ENABLE_SIG_sphincs_sha2_256f_simple_avx2
 
     OQS_STATUS rc;
     FILE *fp_sig = fopen("txt/forged_signature.txt", "r");
     FILE *fp_pub = fopen("txt/pub_key.txt", "r");
     
     uint8_t public_key[OQS_SIG_sphincs_sha2_256f_simple_length_public_key];
     uint8_t secret_key[OQS_SIG_sphincs_sha2_256f_simple_length_secret_key];
     unsigned long int mlen;
     uint8_t signature[OQS_SIG_sphincs_sha2_256f_simple_length_signature];
     int ret_val;


     
    if (!ReadHex(fp_pub, public_key, OQS_SIG_sphincs_sha2_256f_simple_length_public_key, "pk = "))
    {
        printf("ERROR: unable to read 'pk' from <%s>\n", "fn_req");
        return EXT_DATA_ERROR;
    }


    if (FindMarker(fp_sig, "mlen = "))
        ret_val = fscanf(fp_sig, "%lu", &mlen);
        
    else
    {
        printf("ERROR: unable to read 'mlen' from <%s>\n", "fp_sig");
        return EXT_DATA_ERROR;
    }

    if (ret_val != 1) {
        printf("ERROR: unable to parse 'mlen' from <%s>\n", "fp_sig");
        return EXT_DATA_ERROR;
    }

    uint8_t *message = OQS_MEM_malloc(mlen);

    if (!ReadHex(fp_sig, message, (int)mlen, "msg = "))
    {
        printf("ERROR: unable to read 'msg' from <%s>\n", "fn_req");
        return EXT_DATA_ERROR;
    }

    
    if (!ReadHex(fp_sig, signature, OQS_SIG_sphincs_sha2_256f_simple_length_signature, "forged_signature = "))
    {
        printf("ERROR: unable to read 'signature' from <%s>\n", "fn_req");
        return EXT_DATA_ERROR;
    }
 
     rc = OQS_SIG_sphincs_sha2_256f_simple_verify(message, mlen, signature, OQS_SIG_sphincs_sha2_256f_simple_length_signature, public_key);
     if (rc != OQS_SUCCESS) {
         printf("crypto_sign_open returned <-1>\n");
         cleanup_verify(secret_key, OQS_SIG_sphincs_sha2_256f_simple_length_secret_key);
         return OQS_ERROR;
     }
 
     printf("signature is verified succesfully.\n");
     cleanup_verify(secret_key, OQS_SIG_sphincs_sha2_256f_simple_length_secret_key);
     return OQS_SUCCESS;
 
 #else
 
     printf("[example_verify] OQS_SIG_sphincs_sha2_256f_simple was not enabled at compile-time.\n");
     return OQS_SUCCESS;
 
 #endif
 }
 
 int main(void) {
     OQS_init();
     if (example_verify() == OQS_SUCCESS){
         OQS_destroy();
         return EXIT_SUCCESS;
     } else {
         OQS_destroy();
         return EXIT_FAILURE;
     }
 }
 
 void cleanup_verify(uint8_t *secret_key, size_t secret_key_len) {
     OQS_MEM_cleanse(secret_key, secret_key_len);
 }

 