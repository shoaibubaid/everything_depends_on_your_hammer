#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "wots_forge.h"
#include "utils.h"
#include "utilsx1.h"
#include "hash.h"
#include "thash.h"
#include "wots.h"
#include "wotsx1.h"
#include "address.h"
#include "params.h"
#include "api.h"
#include "rng.h"
#include "fors.h"
#include "merkle.h"
#include "extras.h"
#include "fprintbstr.h"



void find_randomness(unsigned char* R, const unsigned char *msg, unsigned long long mlen, 
                    const uint32_t layer, const uint64_t treevalue, 
                    const uint32_t leafvalue,const uint8_t *sk){
    
    spx_ctx ctx;
    const unsigned char *pk = sk + 2*SPX_N;
    unsigned char mhash[SPX_FORS_MSG_BYTES];
    uint64_t tree = 0;
    uint32_t idx_leaf = 0;
    int comeout = 1;
    uint32_t i = 0;

    memcpy(ctx.sk_seed, sk, SPX_N);
    memcpy(ctx.pub_seed, pk, SPX_N);
    initialize_hash_function(&ctx);

    while(comeout){
        randombytes(R, SPX_N);
        hash_message(mhash, &tree, &idx_leaf, R, pk, msg, mlen, &ctx);
        for (i = 0; i < layer; i++) {
            idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT)-1));
            tree = tree >> SPX_TREE_HEIGHT;
        }
        if(tree == treevalue && idx_leaf == leafvalue){
            // printf("%d,%ld\n",idx_leaf,tree);
            // printf("checking for R\n");
            comeout = 0;    

        }
    }

}

void calculate_root(unsigned char* root_fill, unsigned char *sig, 
                    const unsigned char* R, const unsigned char *msg,
                    unsigned long long mlen, const uint32_t layer, const uint8_t *sk){
    
    spx_ctx ctx;
    const unsigned char *pk = sk + 2*SPX_N;
    unsigned char mhash[SPX_FORS_MSG_BYTES];
    unsigned char root[SPX_N];
    uint32_t i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};

    memcpy(ctx.sk_seed, sk, SPX_N);
    memcpy(ctx.pub_seed, pk, SPX_N);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

    /* Derive the message digest and leaf index from R, PK and M. */
    hash_message(mhash, &tree, &idx_leaf, R, pk, msg, mlen, &ctx);
    sig += SPX_N;

    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    /* Sign the message hash using FORS. */
    fors_sign(sig, root, mhash, &ctx, wots_addr);
    sig += SPX_FORS_BYTES;

    for (i = 0; i < layer; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        merkle_sign(sig, root, &ctx, wots_addr, tree_addr, idx_leaf);
        sig += SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT)-1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    memcpy(root_fill,root,SPX_N);

}



void find_apt_root(unsigned char* R, unsigned char* Fill_sign, unsigned char* root_send ,
                    const unsigned char *msg, unsigned long long mlen, const uint32_t layer, 
                    const uint64_t treevalue, const uint32_t leafvalue,uint8_t *sk, 
                    const unsigned int lengths_in[SPX_WOTS_LEN]){

    
    // FILE *file = fopen("forge_log/forge_log.txt", "w");
    // FILE *file2 = fopen("forge_log/forge_log_random.txt", "w");
    spx_ctx ctx;
    unsigned char *sig;
    sig = (unsigned char *)calloc(CRYPTO_BYTES, sizeof(unsigned char));
    const unsigned char *pk = sk + 2*SPX_N;
    unsigned char root[SPX_N];
    unsigned int lengths_out[SPX_WOTS_LEN];
    uint32_t i;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};
    int comeout = 1;
    int try = 0;

    memcpy(ctx.sk_seed, sk, SPX_N);
    memcpy(ctx.pub_seed, pk, SPX_N);

    initialize_hash_function(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

    
    while(comeout){
        comeout = 0;
        randombytes(ctx.sk_seed, SPX_N);
        memcpy(sk, ctx.sk_seed, SPX_N);
        initialize_hash_function(&ctx);
        find_randomness(R,msg,mlen,layer,treevalue,leafvalue,sk);
        memcpy(sig,R,SPX_N);
        calculate_root(root,sig,R,msg,mlen,layer,sk);
        chain_lengths(lengths_out, root);
        printf("try number = %d:  ", try++);
        for(i = 0; i < SPX_WOTS_LEN; i++){
            if(lengths_out[i] < lengths_in[i]){
                comeout = 1;
                // fprintbstr(file2,"R = ", R, SPX_N);
                // fprintf(file2,"less at %d\n", i);
                printf("failed at length %d\n", i);
                // fprintf(file,"less at %d\n", i);
                // fprintsteps(file2, "lengths = ",lengths_out,SPX_WOTS_LEN);
                break;
            }
        }
    }
    printf("found an R\n");
// fclose(file);
// fclose(file2);
memcpy(root_send,root,SPX_N);
memcpy(Fill_sign,sig,(SPX_N + SPX_FORS_BYTES) + layer * (SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N));

}
