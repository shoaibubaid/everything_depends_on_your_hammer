#include <string.h>
#include <stdio.h>
#include <ctype.h>


#include "utils.h"
#include "utilsx1.h"
#include "params.h"
#include "thash.h"
#include "address.h"
#include "fprintbstr.h"

/*
 * Generate the entire Merkle tree, computing the authentication path for
 * leaf_idx, and the resulting root node using Merkle's TreeHash algorithm.
 * Expects the layer and tree parts of the tree_addr to be set, as well as the
 * tree type (i.e. SPX_ADDR_TYPE_HASHTREE or SPX_ADDR_TYPE_FORSTREE)
 *
 * This expects tree_addr to be initialized to the addr structures for the
 * Merkle tree nodes
 *
 * Applies the offset idx_offset to indices before building addresses, so that
 * it is possible to continue counting indices across trees.
 *
 * This works by using the standard Merkle tree building algorithm,
 */
void treehashx1_extra(unsigned char *root, unsigned char *auth_path,
                const spx_ctx* ctx,
                uint32_t leaf_idx, uint32_t idx_offset,
                uint32_t tree_height,
                void (*gen_leaf)(
                   unsigned char* /* Where to write the leaves */,
                   const spx_ctx* /* ctx */,
                   uint32_t idx, void *info),
                uint32_t tree_addr[8],
                void *info)
{
    /* This is where we keep the intermediate nodes */
    SPX_VLA(uint8_t, stack, tree_height*SPX_N); //means uint8_t stack[tree_height*SPX_N]

    uint32_t idx;
    uint32_t max_idx = (uint32_t)((1 << tree_height) - 1);
    for (idx = 0;; idx++) {
        unsigned char current[2*SPX_N];   
            /* Current logical node is at */
            /* index[SPX_N].  We do this to minimize the number of copies */
            /* needed during a thash */
        gen_leaf( &current[SPX_N], ctx, idx + idx_offset,
                    info );

        /* Now combine the freshly generated right node with previously */
        /* generated left ones */
        uint32_t internal_idx_offset = idx_offset;
        uint32_t internal_idx = idx;
        uint32_t internal_leaf = leaf_idx;
        uint32_t h;     /* The height we are in the Merkle tree */
        for (h=0;; h++, internal_idx >>= 1, internal_leaf >>= 1) {

            /* Check if we hit the top of the tree */
            if (h == tree_height) {
                /* We hit the root; return it */
                memcpy( root, &current[SPX_N], SPX_N );
                return;
            }

            /*
             * Check if the node we have is a part of the
             * authentication path; if it is, write it out
             */
            if ((internal_idx ^ internal_leaf) == 0x01) {
                memcpy( &auth_path[ h * SPX_N ],
                        &current[SPX_N],
                        SPX_N );
            }

            /*
             * Check if we're at a left child; if so, stop going up the stack
             * Exception: if we've reached the end of the tree, keep on going
             * (so we combine the last 4 nodes into the one root node in two
             * more iterations)
             */
            if ((internal_idx & 1) == 0 && idx < max_idx) {
                break;
            }

            /* Ok, we're at a right node */
            /* Now combine the left and right logical nodes together */

            /* Set the address of the node we're creating. */
            internal_idx_offset >>= 1;
            set_tree_height(tree_addr, h + 1);
            set_tree_index(tree_addr, internal_idx/2 + internal_idx_offset );

            unsigned char *left = &stack[h * SPX_N];
            memcpy( &current[0], left, SPX_N ); //same memcpy( current, left, SPX_N );like memcpy( current, left, SPX_N );
            // current[0] = current[0] ^ 0xab; 
            // FILE *file = fopen("current.txt", "a");
            // for(int j = 0; j < 2*SPX_N; j++){
                // fprintf(file, "current [%d] = ", j);
                // fprintbstr(file, " ", current, 32);
            // }
            // fclose(file);
            thash( &current[1 * SPX_N],
                   &current[0 * SPX_N],
                   2, ctx, tree_addr);
        }

        /* We've hit a left child; save the current for when we get the */
        /* corresponding right right */
        memcpy( &stack[h * SPX_N], &current[SPX_N], SPX_N);
        // the hashed value is saved in current and then saved on stack
    }
}


void treehashx1_faulted(unsigned char *root, unsigned char *auth_path,
                const spx_ctx* ctx,
                uint32_t leaf_idx, uint32_t idx_offset,
                uint32_t tree_height,
                void (*gen_leaf)(
                   unsigned char* /* Where to write the leaves */,
                   const spx_ctx* /* ctx */,
                   uint32_t idx, void *info),
                uint32_t tree_addr[8],
                void *info)
{
    /* This is where we keep the intermediate nodes */
    SPX_VLA(uint8_t, stack, tree_height*SPX_N);


    FILE *file = fopen("current.txt", "a");

    int count = 0;
    uint32_t idx;
    uint32_t max_idx = (uint32_t)((1 << tree_height) - 1);
    for (idx = 0;; idx++) {
        unsigned char current[2*SPX_N];   /* Current logical node is at */
            /* index[SPX_N].  We do this to minimize the number of copies */
            /* needed during a thash */
        gen_leaf( &current[SPX_N], ctx, idx + idx_offset,
                    info );

        /* Now combine the freshly generated right node with previously */
        /* generated left ones */
        uint32_t internal_idx_offset = idx_offset;
        uint32_t internal_idx = idx;
        uint32_t internal_leaf = leaf_idx;
        uint32_t h;     /* The height we are in the Merkle tree */
        for (h=0;; h++, internal_idx >>= 1, internal_leaf >>= 1) {
        
        // fprintf(file, "idx = %d, h = %d ", idx, h);
        // fprintbstr(file, "current value = ",&current[SPX_N], SPX_N );

            /* Check if we hit the top of the tree */
            if (h == tree_height) {
                /* We hit the root; return it */
                memcpy( root, &current[SPX_N], SPX_N );
                return;
            }

            /*
             * Check if the node we have is a part of the
             * authentication path; if it is, write it out
             */
            if ((internal_idx ^ internal_leaf) == 0x01) {
                memcpy( &auth_path[ h * SPX_N ],
                        &current[SPX_N],
                        SPX_N );
            }

            /*
             * Check if we're at a left child; if so, stop going up the stack
             * Exception: if we've reached the end of the tree, keep on going
             * (so we combine the last 4 nodes into the one root node in two
             * more iterations)
             */
            if ((internal_idx & 1) == 0 && idx < max_idx) {
                break;
            }

            /* Ok, we're at a right node */
            /* Now combine the left and right logical nodes together */

            /* Set the address of the node we're creating. */
            internal_idx_offset >>= 1;
            set_tree_height(tree_addr, h + 1);
            set_tree_index(tree_addr, internal_idx/2 + internal_idx_offset );
            

            // -----------------------------
            fprintbstr(file, "stack before = ", &stack[h * SPX_N], SPX_N);
            if(h != 2 ){count = 1;} //fault can be exploited if h is in (0,1,2) but not 3
            else{count = 0;}
            if(count == 0){
                // current[0] = current[0] ^ 0x01;
                // current[1] = current[1] ^ 0x01;
                // stack[h * SPX_N] = stack[h * SPX_N] ^ 0x11;
                count++;
            }
            fprintbstr(file, "stack after = ", &stack[h * SPX_N], SPX_N);

            // -----------------------------
            unsigned char *left = &stack[h * SPX_N];
            memcpy( &current[0], left, SPX_N );
            if(count == 0){
                // current[0] = current[0] ^ 0x01;
                // current[1] = current[1] ^ 0x01;
            }
            // count++;
            // for(int j = 0; j < 2*SPX_N; j++){
            for(int j = 0; j < 1; j++){
                // fprintf(file, "current [%d] = ", j);
                // fprintbstr(file, " ", &current[j],1);
                // fprintbstr(file, " ", current,32);
            }
            
            
            thash( &current[1 * SPX_N],
                   &current[0 * SPX_N],
                   2, ctx, tree_addr);
        }

        /* We've hit a left child; save the current for when we get the */
        /* corresponding right right */
        memcpy( &stack[h * SPX_N], &current[SPX_N], SPX_N);
        // fprintbstr(file, "stack = ", &stack[h * SPX_N], SPX_N);
         
    }

    fclose(file);
}
