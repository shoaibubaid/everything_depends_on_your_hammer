#include <stdint.h>
#include <string.h>

#include "utils.h"
#include "hash.h"
#include "thash.h"
#include "wots.h"
#include "wotsx1.h"
#include "address.h"
#include "params.h"
#include "api.h"

void wots_forge(unsigned char *pk, unsigned int lengths[SPX_WOTS_LEN], const unsigned char *known_values, const unsigned char *root_msg, const spx_ctx *ctx, uint32_t addr[8]);
int controlled_merkle_sign(uint8_t *sig, unsigned char root[SPX_N], unsigned char *source, unsigned int lengths[SPX_WOTS_LEN], uint32_t layer, uint64_t tree, uint32_t idx_leaf, const uint8_t *sk);
int extract_unfaulted_key_info(uint32_t *obtained_idx_leaf,
                                    uint64_t *obtained_tree, unsigned int *obtained_correct_bi_values,
                                    unsigned char *obtained_wots_sig,
                                    unsigned char *obtained_wots_pk, unsigned char *xmss_auth, unsigned char *obtained_root,
                                    const int layer, const uint8_t *sig, size_t siglen,
                                    const uint8_t *m, size_t mlen, const uint8_t *pk);

int extract_faulted_key_info(uint32_t *obtained_idx_leaf,
                                  uint64_t *obtained_tree, unsigned int *obtained_correct_bi_values,
                                  unsigned char *obtained_wots_sig,
                                  unsigned char *obtained_wots_pk, unsigned char *xmss_auth, unsigned char *obtained_root,
                                  const int layer, const uint8_t *sig, size_t siglen,
                                  const uint8_t *m, size_t mlen, const uint8_t *pk, char *fp_wots_pk_filename);