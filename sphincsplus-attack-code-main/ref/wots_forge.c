#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

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
#include "randombytes.h"
#include "fors.h"
#include "merkle.h"
#include "fprintbstr.h"

static void gen_chain_forge(unsigned char *out, const unsigned char *in,
                            unsigned int start, unsigned int steps,
                            const spx_ctx *ctx, uint32_t addr[8])
{
    uint32_t i;

    /* Initialize out with the value at position 'start'. */
    memcpy(out, in, SPX_N);

    /* Iterate 'steps' calls to the hash function. */
    for (i = start; i < (start + steps) && i < SPX_WOTS_W; i++)
    {
        set_hash_addr(addr, i);
        thash(out, out, 1, ctx, addr);
    }
}

void wots_forge(unsigned char *pk, unsigned int lengths[SPX_WOTS_LEN],
                const unsigned char *known_values, const unsigned char *root_msg,
                const spx_ctx *ctx, uint32_t addr[8])
{
    uint32_t i;
    unsigned int lengths_out[SPX_WOTS_LEN];
    chain_lengths(lengths_out, root_msg);

    for (i = 0; i < SPX_WOTS_LEN; i++)
    {
        set_chain_addr(addr, i);
        gen_chain_forge(pk + i * SPX_N, known_values + i * SPX_N,
                        lengths[i], lengths_out[i] - lengths[i], ctx, addr);
    }
}

void extract_bi_values(unsigned int lengths[SPX_WOTS_LEN], const unsigned char *wots_sig,
                       const unsigned char *wots_pk, const spx_ctx *ctx, uint32_t addr[8])
{
    memset(lengths, -1, SPX_WOTS_LEN);
    unsigned char out[SPX_WOTS_BYTES];
    int i;
    for (i = 0; i < SPX_WOTS_LEN; i++)
    {
        for (int j = 0; j < SPX_WOTS_W; j++)
        {
            set_chain_addr(addr, i);
            gen_chain_forge(out + i * SPX_N, wots_sig + i * SPX_N,
                            j, SPX_WOTS_W - 1 - j, ctx, addr);
            if (memcmp(out + i * SPX_N, wots_pk + i * SPX_N, SPX_N) == 0)
            {
                lengths[i] = j;
                break;
            }
            lengths[i] = 50; // why put 50 specifically?
        }
    }
}

int controlled_merkle_sign(uint8_t *sig, unsigned char root[SPX_N], unsigned char *source,
                           unsigned int lengths[SPX_WOTS_LEN], uint32_t layer, uint64_t tree,
                           uint32_t idx_leaf, const uint8_t *sk)
{
    spx_ctx ctx;
    const unsigned char *pk = sk + 2 * SPX_N;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};

    memcpy(ctx.sk_seed, sk, SPX_N);
    memcpy(ctx.pub_seed, pk, SPX_N);

    initialize_hash_function(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    set_layer_addr(tree_addr, layer);
    set_tree_addr(tree_addr, tree);

    copy_subtree_addr(wots_addr, tree_addr);
    set_keypair_addr(wots_addr, idx_leaf);

    wots_forge(sig, lengths, source, root, &ctx, wots_addr);

    return 0;
}

int extract_unfaulted_key_info(uint32_t *obtained_idx_leaf,
                               uint64_t *obtained_tree, unsigned int *obtained_correct_bi_values,
                               unsigned char *obtained_wots_sig,
                               unsigned char *obtained_wots_pk, unsigned char *xmss_auth, unsigned char *obtained_root,
                               const int layer, const uint8_t *sig, size_t siglen,
                               const uint8_t *m, size_t mlen, const uint8_t *pk)
{
    spx_ctx ctx;
    const unsigned char *pub_root = pk + SPX_N;
    unsigned char mhash[SPX_FORS_MSG_BYTES];
    unsigned char wots_pk[SPX_WOTS_BYTES];
    unsigned char root[SPX_N];
    unsigned char leaf[SPX_N];
    unsigned int i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};
    uint32_t wots_pk_addr[8] = {0};

    unsigned int lengths[SPX_WOTS_LEN];

    if (siglen != SPX_BYTES)
    {
        return -1;
    }
    memcpy(ctx.pub_seed, pk, SPX_N);

    /* This hook allows the hash function instantiation to do whatever
    preparation or computation it needs, based on the public seed. */
    initialize_hash_function(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
    set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    /* Derive the message digest and leaf index from R || PK || M. */
    /* The additional SPX_N is a result of the hash domain separator. */
    hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
    sig += SPX_N;

    /* Layer correctly defaults to 0, so no need to set_layer_addr */
    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    fors_pk_from_sig(root, sig, mhash, &ctx, wots_addr);
    sig += SPX_FORS_BYTES;

    /* For each subtree.. */
    for (i = 0; i < SPX_D; i++)
    {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        chain_lengths(lengths, root);

        if (i == layer)
        {
            memcpy(obtained_correct_bi_values, lengths, sizeof(unsigned int) * SPX_WOTS_LEN);
            *obtained_idx_leaf = idx_leaf;
            *obtained_tree = tree;
        }

        copy_keypair_addr(wots_pk_addr, wots_addr);

        /* The WOTS public key is only correct if the signature was correct. */
        /* Initially, root is the FORS pk, but on subsequent iterations it is
        the root of the subtree below the currently processed subtree. */

        wots_pk_from_sig(wots_pk, sig, root, &ctx, wots_addr);

        if (i == layer)
        {
            memcpy(obtained_wots_sig, sig, SPX_WOTS_BYTES);
            memcpy(obtained_wots_pk, wots_pk, SPX_WOTS_BYTES);
        }
        sig += SPX_WOTS_BYTES;

        if (i == layer)
        {
            memcpy(xmss_auth, sig, SPX_TREE_HEIGHT * SPX_N);
        }

        /* Compute the leaf node using the WOTS public key. */
        thash(leaf, wots_pk, SPX_WOTS_LEN, &ctx, wots_pk_addr);

        /* Compute the root node of this subtree. */
        compute_root(root, leaf, idx_leaf, 0, sig, SPX_TREE_HEIGHT,
                     &ctx, tree_addr);

        if (i == layer)
        {
            memcpy(obtained_root, root, SPX_N);
        }

        sig += SPX_TREE_HEIGHT * SPX_N;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT) - 1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    /* Check if the root node equals the root node in the public key. */
    if (memcmp(root, pub_root, SPX_N))
    {
        return -1;
    }

    return 0;
}

int extract_faulted_key_info(uint32_t *obtained_idx_leaf,
                             uint64_t *obtained_tree, unsigned int *obtained_correct_bi_values,
                             unsigned char *obtained_wots_sig,
                             unsigned char *obtained_wots_pk, unsigned char *xmss_auth, unsigned char *obtained_root,
                             const int layer, const uint8_t *sig, size_t siglen,
                             const uint8_t *m, size_t mlen, const uint8_t *pk, char *fp_wots_pk_filename)
{
    char fp_buffer[50];
    FILE *fp_wots_pk = fopen(fp_wots_pk_filename,"r");
    spx_ctx ctx;
    const unsigned char *pub_root = pk + SPX_N;
    unsigned char mhash[SPX_FORS_MSG_BYTES];
    unsigned char wots_pk_check[SPX_WOTS_BYTES];
    unsigned char wots_pk[SPX_WOTS_BYTES];
    unsigned char root[SPX_N];
    unsigned char leaf[SPX_N];
    unsigned char wots_sig[SPX_WOTS_BYTES];
    unsigned int lengths[SPX_WOTS_LEN];
    unsigned int i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};
    uint32_t wots_pk_addr[8] = {0};

    if (siglen != SPX_BYTES)
    {
        return -1;
    }
    memcpy(ctx.pub_seed, pk, SPX_N);

    /* This hook allows the hash function instantiation to do whatever
    preparation or computation it needs, based on the public seed. */
    initialize_hash_function(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
    set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    /* Derive the message digest and leaf index from R || PK || M. */
    /* The additional SPX_N is a result of the hash domain separator. */
    hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
    sig += SPX_N;

    /* Layer correctly defaults to 0, so no need to set_layer_addr */
    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    fors_pk_from_sig(root, sig, mhash, &ctx, wots_addr);
    sig += SPX_FORS_BYTES;

    /* For each subtree.. */
    for (i = 0; i < SPX_D; i++)
    {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        if (i == layer)
        {

            *obtained_idx_leaf = idx_leaf;
            *obtained_tree = tree;
        }

        memcpy(wots_sig, sig, SPX_WOTS_BYTES);

        if (i == layer)
        {
            sprintf(fp_buffer, "pk%d = ", idx_leaf);
            // if (!ReadHex(fp_wots_pk, wots_pk_check, SPX_WOTS_BYTES, fp_buffer))
            if (!ReadHex(fp_wots_pk, wots_pk_check, SPX_WOTS_BYTES, fp_buffer))
            {
                printf("ERROR: unable to read 'wots_pk' from <%s>\n", "fn_req");
                return -1;
            }
        }

        extract_bi_values(lengths, wots_sig, wots_pk_check, &ctx, wots_addr);
        memcpy(obtained_correct_bi_values, lengths, sizeof(unsigned int) * SPX_WOTS_LEN);

        copy_keypair_addr(wots_pk_addr, wots_addr);

        /* The WOTS public key is only correct if the signature was correct. */
        /* Initially, root is the FORS pk, but on subsequent iterations it is
        the root of the subtree below the currently processed subtree. */

        wots_pk_from_sig(wots_pk, sig, root, &ctx, wots_addr);

        if (i == layer)
        {
            memcpy(obtained_wots_sig, sig, SPX_WOTS_BYTES);
            memcpy(obtained_wots_pk, wots_pk, SPX_WOTS_BYTES);
        }
        sig += SPX_WOTS_BYTES;

        if (i == layer)
        {
            memcpy(xmss_auth, sig, SPX_TREE_HEIGHT * SPX_N);
        }

        /* Compute the leaf node using the WOTS public key. */
        thash(leaf, wots_pk, SPX_WOTS_LEN, &ctx, wots_pk_addr);

        /* Compute the root node of this subtree. */
        compute_root(root, leaf, idx_leaf, 0, sig, SPX_TREE_HEIGHT,
                     &ctx, tree_addr);

        if (i == layer)
        {
            memcpy(obtained_root, root, SPX_N);
        }
        sig += SPX_TREE_HEIGHT * SPX_N;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT) - 1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    /* Check if the root node equals the root node in the public key. */
    if (memcmp(root, pub_root, SPX_N))
    {
        return -1;
    }

    return 0;
}
