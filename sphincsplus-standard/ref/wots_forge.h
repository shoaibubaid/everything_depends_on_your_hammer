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

void wots_forge_test(unsigned char *pk, unsigned int lengths[SPX_WOTS_LEN], const unsigned char *known_values, const unsigned char *root_msg, const spx_ctx *ctx, uint32_t addr[8]);
int controlled_merkle_sign(uint8_t *sig, unsigned char root[SPX_N], unsigned char *source, unsigned int lengths[SPX_WOTS_LEN], uint32_t layer, uint64_t tree, uint32_t idx_leaf, const uint8_t *sk);
int crypto_sign_signature_test(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen, const uint8_t *sk);
int crypto_sign_verify_test(const uint8_t *sig, size_t siglen,const uint8_t *m, size_t mlen, const uint8_t *pk);
void fault(uint64_t* tree, int fault_tree);

int crypto_sign_test(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen,
                const unsigned char *sk);

int crypto_sign_open_test(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk);

