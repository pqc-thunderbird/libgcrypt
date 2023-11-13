#if !defined(WOTSX1_H_)
#define WOTSX1_H_

#include "config.h"
#include <string.h>
#include "g10lib.h"

struct _gcry_slhdsa_leaf_info_x1_t
{
  unsigned char *wots_sig;
  u32 wots_sign_leaf; /* The index of the WOTS we're using to sign */
  u32 *wots_steps;
  u32 leaf_addr[8];
  u32 pk_addr[8];
};

gcry_err_code_t _gcry_slhdsa_wots_gen_leafx1(unsigned char *dest,
                                             const _gcry_slhdsa_param_t *ctx,
                                             u32 leaf_idx,
                                             void *v_info);

#endif /* WOTSX1_H_ */
