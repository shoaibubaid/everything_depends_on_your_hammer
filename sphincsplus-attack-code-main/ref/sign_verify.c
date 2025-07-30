#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "api.h"
#include "fprintbstr.h"
#include "wots_forge.h"

#define NO_OF_LEAVES (1 << SPX_TREE_HEIGHT)
#define EXT_SUCCESS 0
#define EXT_FILE_OPEN_ERROR -1
#define EXT_DATA_ERROR -3
#define EXT_CRYPTO_FAILURE -4

int main()
{
    char fp_buffer[50];
    int ret_val, count, done, i;
    FILE *fp_sig, *fp_pub, *fp_rsp, *fp_wots_pk_rsp, *fp_fault_sig, *fp_fault_sig_rsp;

    fp_rsp = fopen("extracted/extracted_unfaulted_results.txt", "w");
    fp_fault_sig_rsp = fopen("extracted/extracted_faulted_results.txt", "w");
    fp_wots_pk_rsp = fopen("extracted/extracted_wots_pk.txt", "w");
    fp_sig = fopen("out/forged_signature.txt", "r");
    fp_pub = fopen("out/collected_pubkey.txt", "r");
    fp_fault_sig = fopen("in/collected_faulty_sig.txt", "r");

    unsigned char collected_wots_pk_array[NO_OF_LEAVES * SPX_WOTS_BYTES] = {0};
    unsigned char *message;
    unsigned char signature[CRYPTO_BYTES];
    unsigned char pub_key[CRYPTO_PUBLICKEYBYTES];
    unsigned char obtained_wots_sig[SPX_WOTS_BYTES], obtained_wots_pk[SPX_WOTS_BYTES], xmss_auth[SPX_TREE_HEIGHT * SPX_N];
    unsigned long long mlen;
    uint64_t obtained_tree;
    uint32_t obtained_idx_leaf;
    unsigned char obtained_root[SPX_N];
    unsigned int obtained_correct_bi_values[SPX_WOTS_LEN];
    int layer = SPX_D - 1;

    if (!ReadHex(fp_pub, pub_key, CRYPTO_PUBLICKEYBYTES, "pk = "))
    {
        printf("ERROR: unable to read 'pk' from <%s>\n", "fn_req");
        return EXT_DATA_ERROR;
    }
    fprintbstr(fp_rsp, "pk = ", pub_key, CRYPTO_PUBLICKEYBYTES);


    if (FindMarker(fp_sig, "mlen = "))
        ret_val = fscanf(fp_sig, "%llu", &mlen);
    else
    {
        printf("ERROR: unable to read 'mlen' from <%s>\n", "fp_sig");
        return EXT_DATA_ERROR;
    }
    fprintf(fp_rsp, "mlen = %llu\n", mlen);

    message = (unsigned char *)calloc(mlen, sizeof(unsigned char));

    if (!ReadHex(fp_sig, message, (int)mlen, "msg = "))
    {
        printf("ERROR: unable to read 'msg' from <%s>\n", "fn_req");
        return EXT_DATA_ERROR;
    }
    fprintbstr(fp_rsp, "msg = ", message, mlen);

    if (!ReadHex(fp_sig, signature, CRYPTO_BYTES, "forged_signature = "))
    {
        printf("ERROR: unable to read 'signature' from <%s>\n", "fn_req");
        return EXT_DATA_ERROR;
    }
    // fprintbstr(fp_rsp, "signature = ", signature, CRYPTO_BYTES);

    

    if(ret_val = crypto_sign_verify(signature, CRYPTO_BYTES, message, mlen, pub_key) != 0) {
        printf("crypto_sign_open returned <%d>\n", ret_val);
        return EXT_CRYPTO_FAILURE; 
    }
    
    printf("signature verified and is a correct signature\n");

    return 0;
}
