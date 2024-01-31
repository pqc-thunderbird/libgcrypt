/* mldsa-shuffle-avx2.S
 * Copyright (C) 2024 MTG AG
 * The code was created based on the reference implementation that is part of the ML-DSA NIST submission.
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "mldsa-consts-avx2.h"
.include "mldsa-shuffle-avx2.inc"

.text
nttunpack128_avx:
#load
vmovdqa		(%rdi),%ymm4
vmovdqa		32(%rdi),%ymm5
vmovdqa		64(%rdi),%ymm6
vmovdqa		96(%rdi),%ymm7
vmovdqa		128(%rdi),%ymm8
vmovdqa		160(%rdi),%ymm9
vmovdqa		192(%rdi),%ymm10
vmovdqa		224(%rdi),%ymm11

shuffle8	4,8,3,8
shuffle8	5,9,4,9
shuffle8	6,10,5,10
shuffle8	7,11,6,11

shuffle4	3,5,7,5
shuffle4	8,10,3,10
shuffle4	4,6,8,6
shuffle4	9,11,4,11

shuffle2	7,8,9,8
shuffle2	5,6,7,6
shuffle2	3,4,5,4
shuffle2	10,11,3,11

#store
vmovdqa		%ymm9,(%rdi)
vmovdqa		%ymm8,32(%rdi)
vmovdqa		%ymm7,64(%rdi)
vmovdqa		%ymm6,96(%rdi)
vmovdqa		%ymm5,128(%rdi)
vmovdqa		%ymm4,160(%rdi)
vmovdqa		%ymm3,192(%rdi)
vmovdqa		%ymm11,224(%rdi)

ret

.global cdecl(_gcry_mldsa_avx2_nttunpack_avx)
cdecl(_gcry_mldsa_avx2_nttunpack_avx):
call		nttunpack128_avx
add		$256,%rdi
call		nttunpack128_avx
add		$256,%rdi
call		nttunpack128_avx
add		$256,%rdi
call		nttunpack128_avx
ret
