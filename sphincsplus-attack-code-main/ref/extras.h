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
#include "rng.h"
#include "fors.h"
#include "merkle.h"

void find_randomness(unsigned char* R, const unsigned char *msg,
                    unsigned long long mlen, const uint32_t layer,
                    const uint64_t treevalue, const uint32_t leafvalue,const uint8_t *sk);
                    
void calculate_root(unsigned char* root_fill, unsigned char *sig, const unsigned char* R, 
                    const unsigned char *msg, unsigned long long mlen, const uint32_t layer, 
                    const uint8_t *sk);

void find_apt_root( unsigned char* R, unsigned char* Fill_sign, 
                    unsigned char* root_send ,const unsigned char *msg, 
                    unsigned long long mlen, const uint32_t layer, 
                    const uint64_t treevalue, const uint32_t leafvalue,
                    uint8_t *sk, const unsigned int lengths_in[SPX_WOTS_LEN]);