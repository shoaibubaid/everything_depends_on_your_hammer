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
#define MAX_BUFFER_SIZE 50

int main()
{   
    char address_buffer[30];
    char fp_buffer[MAX_BUFFER_SIZE];
    int ret_val, count, done, i, layer;
    unsigned char collected_wots_pk_array[NO_OF_LEAVES * SPX_WOTS_BYTES] = {0};
    unsigned char *message;
    unsigned char signature[CRYPTO_BYTES];
    unsigned char pub_key[CRYPTO_PUBLICKEYBYTES];
    unsigned char obtained_wots_sig[SPX_WOTS_BYTES], obtained_wots_pk[SPX_WOTS_BYTES], xmss_auth[SPX_TREE_HEIGHT * SPX_N];
    unsigned long long mlen;
    unsigned char obtained_root[SPX_N];
    unsigned int obtained_correct_bi_values[SPX_WOTS_LEN];
    uint64_t obtained_tree;
    uint32_t obtained_idx_leaf;
    FILE *fp_sig, *fp_pub, *fp_rsp, *fp_wots_pk_rsp, *fp_fault_sig, *fp_fault_sig_rsp;
    
    layer = SPX_D - 1;
    fp_fault_sig_rsp = fopen("extracted/extracted_faulted_results.txt", "w");
    // fp_wots_pk_rsp = fopen("extracted/extracted_wots_pk.txt", "r");
    fp_pub = fopen("in/collected_pubkey.txt", "r");
    fp_fault_sig = fopen("in/collected_faulty_sig.txt", "r");
    sprintf(fp_buffer, "extracted/extracted_wots_pk.txt");

    if (!ReadHex(fp_pub, pub_key, CRYPTO_PUBLICKEYBYTES, "pk = "))
    {
        printf("ERROR: unable to read 'pk' from <%s>\n", "fn_req");
        return EXT_DATA_ERROR;
    }
    // fprintbstr(fp_rsp, "pk = ", pub_key, CRYPTO_PUBLICKEYBYTES);

    
    done = 0;
    do
    {   
         if (FindMarker(fp_fault_sig, "address = "))
            ret_val = fscanf(fp_fault_sig, "%s", address_buffer);
        else
        {   
            done = 1;
            break;
            // printf("ERROR: unable to read 'address' from <%s>\n", "the given file");
            // return EXT_DATA_ERROR;
        }
        fprintf(fp_fault_sig_rsp, "address = %s\n", address_buffer);

        if (FindMarker(fp_fault_sig, "count = "))
            ret_val = fscanf(fp_fault_sig, "%d", &count);
        else
        {
            done = 1;
            break;
        }
        fprintf(fp_fault_sig_rsp, "count = %d\n", count);

        if (FindMarker(fp_fault_sig, "mlen = "))
            ret_val = fscanf(fp_fault_sig, "%llu", &mlen);
        else
        {
            printf("ERROR: unable to read 'mlen' from <%s>\n", "fp_sig");
            return EXT_DATA_ERROR;
        }
        fprintf(fp_fault_sig_rsp, "mlen = %llu\n", mlen);

        message = (unsigned char *)calloc(mlen, sizeof(unsigned char));

        if (!ReadHex(fp_fault_sig, message, (int)mlen, "msg = "))
        {
            printf("ERROR: unable to read 'msg' from <%s>\n", "fn_msg");
            return EXT_DATA_ERROR;
        }
        fprintbstr(fp_fault_sig_rsp, "msg = ", message, mlen);

        if (!ReadHex(fp_fault_sig, signature, CRYPTO_BYTES, "signature = "))
        {
            printf("ERROR: unable to read 'signature' from <%s>\n", "fn_req");
            return EXT_DATA_ERROR;
        }
        // fprintbstr(fp_fault_sig_rsp, "signature = ", signature, CRYPTO_BYTES);
    

        
        extract_faulted_key_info(&obtained_idx_leaf, &obtained_tree, obtained_correct_bi_values, obtained_wots_sig, obtained_wots_pk, xmss_auth, obtained_root, layer, signature, CRYPTO_BYTES, message, mlen, pub_key, fp_buffer);

        fprintf(fp_fault_sig_rsp, "layer = %d\n", layer);
        fprintf(fp_fault_sig_rsp, "tree = %ld\nleaf = %d\n", obtained_tree, obtained_idx_leaf);
        fprintsteps(fp_fault_sig_rsp, "lengths = ", obtained_correct_bi_values, SPX_WOTS_LEN);
        fprintbstr(fp_fault_sig_rsp, "wots_sign = ", obtained_wots_sig, SPX_WOTS_BYTES);
        fprintbstr(fp_fault_sig_rsp, "wots_pk = ", obtained_wots_pk, SPX_WOTS_BYTES);
        fprintbstr(fp_fault_sig_rsp, "xmss_auth = ", xmss_auth, SPX_TREE_HEIGHT * SPX_N);
        fprintbstr(fp_fault_sig_rsp, "root = ", obtained_root, SPX_N);
        printf("completed for count = %d\n", count);
    } while (!done);

    printf("values extracted to file extracted results.txt\n");

    return EXT_SUCCESS;
}
