#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include "rng.h"
#include "api.h"
#include "fprintbstr.h"
#include "wots_forge.h"

#define MAX_MARKER_LEN 50

#define KAT_SUCCESS 0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR -3
#define KAT_CRYPTO_FAILURE -4

#define MAX_ITERARIONS 1

int main(void)
{   
    srand(time(NULL));
    // unsigned char entropy_input[CRYPTO_SEEDBYTES] = {0};
    unsigned char entropy_input[CRYPTO_SEEDBYTES];
    for (int i = 0; i < CRYPTO_SEEDBYTES; i++) {
        entropy_input[i] = (unsigned char)(rand() % 256);
    }
    /*setting up for random number*/
    
    int random_number = (rand() % 10);
    // printf("random number = %d\n", random_number);
    unsigned char random_values[1000];

    /*setting up the integers*/
    FILE *fp_pub, *fp_message;
    FILE *file = fopen("signature.txt", "w");
    // unsigned char entropy_input[CRYPTO_SEEDBYTES] = {0};
    unsigned char msg[3300] = "123456789abcdef123456789abcdef123456789abcdef12345";
    unsigned char *sm, *m1;
    unsigned long long mlen, smlen, mlen1;
    mlen = 40;

    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    fp_pub = fopen("key.txt", "r");
    fp_message = fopen("message_to_forge.txt", "r");

    int ret_val, count;



    if (!ReadHex(fp_pub, sk, CRYPTO_SECRETKEYBYTES, "sk = "))
    {
        printf("ERROR: unable to read 'sk' from <%s>\n", "fn_req");
        return -1;
    }

    if (!ReadHex(fp_pub, pk, CRYPTO_PUBLICKEYBYTES, "pk = "))
    {
        printf("ERROR: unable to read 'pk' from <%s>\n", "fn_req");
        return -1;
    } 

    // if (FindMarker(fp_message, "mlen = "))
    //     ret_val = fscanf(fp_message, "%u", &mlen);
    // else
    // {
    //     printf("ERROR: unable to read 'mlen' from <%s>\n", "fp_message");
    //     return -1;
    // }

    // printf("mlen = %u\n", mlen);
    




    // if (!ReadHex(fp_message, msg, mlen, "message = "))
    // {
    //     printf("ERROR: unable to read 'message' from <%s>\n", "fp_message");
    //     return -1;
    // }
    

    
    randombytes(random_values, 1000);
    // memcpy(entropy_input, random_values,CRYPTO_SEEDBYTES );
    /*initiating the randombytes using entropy as input*/
    randombytes_init(entropy_input, random_values);
    // mlen = 34;
    for (count = 0; count < MAX_ITERARIONS; count++)
    {   
        // random_number = (rand() % 950);
        // printf("random number = %d\n",random_number);
        /*setting up for entropy*/
        // randombytes(random_values, 1000);
        // memcpy(entropy_input, random_values,CRYPTO_SEEDBYTES );
        // /*initiating the randombytes using entropy as input*/
        // randombytes_init(entropy_input, random_values);
        randombytes(msg, mlen);

        

        // m = (unsigned char *)calloc(mlen, sizeof(unsigned char));
        m1 = (unsigned char *)calloc(mlen + CRYPTO_BYTES, sizeof(unsigned char));
        sm = (unsigned char *)calloc(mlen + CRYPTO_BYTES, sizeof(unsigned char));
        

        // fprintf(file, "address = just_to_fill\n");
        fprintf(file, "count = %d\n", count);
        fprintf(file, "mlen = %lld\n", mlen);
        fprintbstr(file, "msg = ", msg, mlen);        
        

        // mlen = 34;
        // crypto_sign(sm, &smlen, msg, mlen, sk);
        crypto_sign(sm, &smlen, msg, mlen, sk);


        
        fprintbstr(file, "signature = ", sm, CRYPTO_BYTES);
        if ((ret_val = crypto_sign_open(m1, &mlen1, sm, smlen, pk)) != 0)
        {
            printf("crypto_sign_open returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }

    }

    

    // free(m);
    free(m1);
    free(sm);
    fclose(file);
    fclose(fp_message);
    fclose(fp_pub);
    return KAT_SUCCESS;
}
