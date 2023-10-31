#if !defined( WOTSX1_H_ )
#define WOTSX1_H_

#include "config.h"
#include <string.h>
#include "g10lib.h"

struct _gcry_slhdsa_leaf_info_x1_t {
    unsigned char *wots_sig;
    uint32_t wots_sign_leaf; /* The index of the WOTS we're using to sign */
    uint32_t *wots_steps;
    uint32_t leaf_addr[8];
    uint32_t pk_addr[8];
};

gcry_err_code_t _gcry_slhdsa_wots_gen_leafx1(unsigned char *dest,
                   const _gcry_slhdsa_param_t *ctx,
                   uint32_t leaf_idx, void *v_info);

#endif /* WOTSX1_H_ */
