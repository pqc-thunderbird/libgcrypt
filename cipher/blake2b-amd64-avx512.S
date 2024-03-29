/* blake2b-amd64-avx512.S  -  AVX512 implementation of BLAKE2b
 *
 * Copyright (C) 2022 Jussi Kivilinna <jussi.kivilinna@iki.fi>
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

/* The code is based on public-domain/CC0 BLAKE2 reference implementation
 * by Samual Neves, at https://github.com/BLAKE2/BLAKE2/tree/master/sse
 * Copyright 2012, Samuel Neves <sneves@dei.uc.pt>
 */

#ifdef __x86_64
#include <config.h>
#if defined(HAVE_GCC_INLINE_ASM_AVX512) && \
   (defined(HAVE_COMPATIBLE_GCC_AMD64_PLATFORM_AS) || \
    defined(HAVE_COMPATIBLE_GCC_WIN64_PLATFORM_AS))

#include "asm-common-amd64.h"

/* register macros */
#define RSTATE  %rdi
#define RINBLKS %rsi
#define RNBLKS  %rdx
#define RIV     %rcx

/* state structure */
#define STATE_H 0
#define STATE_T (STATE_H + 8 * 8)
#define STATE_F (STATE_T + 2 * 8)

/* vector registers */
#define ROW1  %ymm0
#define ROW2  %ymm1
#define ROW3  %ymm2
#define ROW4  %ymm3
#define TMP1  %ymm4
#define TMP1x %xmm4
#define R16   %ymm13

#define MA1   %ymm5
#define MA2   %ymm6
#define MA3   %ymm7
#define MA4   %ymm8
#define MA1x  %xmm5
#define MA2x  %xmm6
#define MA3x  %xmm7
#define MA4x  %xmm8

#define MB1   %ymm9
#define MB2   %ymm10
#define MB3   %ymm11
#define MB4   %ymm12
#define MB1x  %xmm9
#define MB2x  %xmm10
#define MB3x  %xmm11
#define MB4x  %xmm12

/**********************************************************************
  blake2b/AVX2
 **********************************************************************/

/* Load one qword value at memory location MEM to specific element in
 * target register VREG. Note, KPOS needs to contain value "(1 << QPOS)". */
#define VPINSRQ_KMASK(kpos, qpos, mem, vreg) \
        vmovdqu64 -((qpos) * 8) + mem, vreg {kpos}

#define GATHER_MSG(m1, m2, m3, m4, m1x, m2x, m3x, m4x, \
                   s0, s1, s2, s3, s4, s5, s6, s7, s8, \
                   s9, s10, s11, s12, s13, s14, s15) \
        vmovq (s0)*8(RINBLKS), m1x; \
          vmovq (s1)*8(RINBLKS), m2x; \
            vmovq (s8)*8(RINBLKS), m3x; \
              vmovq (s9)*8(RINBLKS), m4x; \
        VPINSRQ_KMASK(%k1, 1, (s2)*8(RINBLKS), m1); \
          VPINSRQ_KMASK(%k1, 1, (s3)*8(RINBLKS), m2); \
            VPINSRQ_KMASK(%k1, 1, (s10)*8(RINBLKS), m3); \
              VPINSRQ_KMASK(%k1, 1, (s11)*8(RINBLKS), m4); \
        VPINSRQ_KMASK(%k2, 2, (s4)*8(RINBLKS), m1); \
          VPINSRQ_KMASK(%k2, 2, (s5)*8(RINBLKS), m2); \
            VPINSRQ_KMASK(%k2, 2, (s12)*8(RINBLKS), m3); \
              VPINSRQ_KMASK(%k2, 2, (s13)*8(RINBLKS), m4); \
        VPINSRQ_KMASK(%k3, 3, (s6)*8(RINBLKS), m1); \
          VPINSRQ_KMASK(%k3, 3, (s7)*8(RINBLKS), m2); \
            VPINSRQ_KMASK(%k3, 3, (s14)*8(RINBLKS), m3); \
              VPINSRQ_KMASK(%k3, 3, (s15)*8(RINBLKS), m4);

#define LOAD_MSG_0(m1, m2, m3, m4, m1x, m2x, m3x, m4x) \
        GATHER_MSG(m1, m2, m3, m4, m1x, m2x, m3x, m4x, \
                    0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15)
#define LOAD_MSG_1(m1, m2, m3, m4, m1x, m2x, m3x, m4x) \
        GATHER_MSG(m1, m2, m3, m4, m1x, m2x, m3x, m4x, \
                   14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3)
#define LOAD_MSG_2(m1, m2, m3, m4, m1x, m2x, m3x, m4x) \
        GATHER_MSG(m1, m2, m3, m4, m1x, m2x, m3x, m4x, \
                   11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4)
#define LOAD_MSG_3(m1, m2, m3, m4, m1x, m2x, m3x, m4x) \
        GATHER_MSG(m1, m2, m3, m4, m1x, m2x, m3x, m4x, \
                    7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8)
#define LOAD_MSG_4(m1, m2, m3, m4, m1x, m2x, m3x, m4x) \
        GATHER_MSG(m1, m2, m3, m4, m1x, m2x, m3x, m4x, \
                    9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13)
#define LOAD_MSG_5(m1, m2, m3, m4, m1x, m2x, m3x, m4x) \
        GATHER_MSG(m1, m2, m3, m4, m1x, m2x, m3x, m4x, \
                    2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9)
#define LOAD_MSG_6(m1, m2, m3, m4, m1x, m2x, m3x, m4x) \
        GATHER_MSG(m1, m2, m3, m4, m1x, m2x, m3x, m4x, \
                   12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11)
#define LOAD_MSG_7(m1, m2, m3, m4, m1x, m2x, m3x, m4x) \
        GATHER_MSG(m1, m2, m3, m4, m1x, m2x, m3x, m4x, \
                   13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10)
#define LOAD_MSG_8(m1, m2, m3, m4, m1x, m2x, m3x, m4x) \
        GATHER_MSG(m1, m2, m3, m4, m1x, m2x, m3x, m4x, \
                    6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5)
#define LOAD_MSG_9(m1, m2, m3, m4, m1x, m2x, m3x, m4x) \
        GATHER_MSG(m1, m2, m3, m4, m1x, m2x, m3x, m4x, \
                   10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0)
#define LOAD_MSG_10(m1, m2, m3, m4, m1x, m2x, m3x, m4x) \
        LOAD_MSG_0(m1, m2, m3, m4, m1x, m2x, m3x, m4x)
#define LOAD_MSG_11(m1, m2, m3, m4, m1x, m2x, m3x, m4x) \
        LOAD_MSG_1(m1, m2, m3, m4, m1x, m2x, m3x, m4x)

#define LOAD_MSG(r, m1, m2, m3, m4) \
        LOAD_MSG_##r(m1, m2, m3, m4, m1##x, m2##x, m3##x, m4##x)

#define ROR_32(in, out) vpshufd $0xb1, in, out

#define ROR_24(in, out) vprorq $24, in, out

#define ROR_16(in, out) vpshufb R16, in, out

#define ROR_63(in, out) vprorq $63, in, out

#define G(r1, r2, r3, r4, m, ROR_A, ROR_B) \
        vpaddq m, r1, r1; \
        vpaddq r2, r1, r1; \
        vpxor r1, r4, r4; \
        ROR_A(r4, r4); \
        vpaddq r4, r3, r3; \
        vpxor r3, r2, r2; \
        ROR_B(r2, r2)

#define G1(r1, r2, r3, r4, m) \
        G(r1, r2, r3, r4, m, ROR_32, ROR_24)

#define G2(r1, r2, r3, r4, m) \
        G(r1, r2, r3, r4, m, ROR_16, ROR_63)

#define MM_SHUFFLE(z,y,x,w) \
        (((z) << 6) | ((y) << 4) | ((x) << 2) | (w))

#define DIAGONALIZE(r1, r2, r3, r4) \
        vpermq $MM_SHUFFLE(0,3,2,1), r2, r2; \
        vpermq $MM_SHUFFLE(1,0,3,2), r3, r3; \
        vpermq $MM_SHUFFLE(2,1,0,3), r4, r4

#define UNDIAGONALIZE(r1, r2, r3, r4) \
        vpermq $MM_SHUFFLE(2,1,0,3), r2, r2; \
        vpermq $MM_SHUFFLE(1,0,3,2), r3, r3; \
        vpermq $MM_SHUFFLE(0,3,2,1), r4, r4

#define ROUND(r, m1, m2, m3, m4) \
        G1(ROW1, ROW2, ROW3, ROW4, m1); \
        G2(ROW1, ROW2, ROW3, ROW4, m2); \
        DIAGONALIZE(ROW1, ROW2, ROW3, ROW4); \
        G1(ROW1, ROW2, ROW3, ROW4, m3); \
        G2(ROW1, ROW2, ROW3, ROW4, m4); \
        UNDIAGONALIZE(ROW1, ROW2, ROW3, ROW4)

SECTION_RODATA

.align 32
ELF(.type _blake2b_avx512_data,@object;)
_blake2b_avx512_data:
.Liv:
        .quad 0x6a09e667f3bcc908, 0xbb67ae8584caa73b
        .quad 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1
        .quad 0x510e527fade682d1, 0x9b05688c2b3e6c1f
        .quad 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
.Lshuf_ror16:
        .byte 2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9
.Lk1_mask:
	.byte (1 << 1)

.text

.align 64
.globl _gcry_blake2b_transform_amd64_avx512
ELF(.type _gcry_blake2b_transform_amd64_avx512,@function;)

_gcry_blake2b_transform_amd64_avx512:
        /* input:
         *	%rdi: state
         *	%rsi: blks
         *	%rdx: num_blks
         */
        CFI_STARTPROC();

        spec_stop_avx512;

        kmovb .Lk1_mask rRIP, %k1;
        kshiftlb $1, %k1, %k2;
        kshiftlb $2, %k1, %k3;

        addq $128, (STATE_T + 0)(RSTATE);
        adcq $0, (STATE_T + 8)(RSTATE);

        vbroadcasti128 .Lshuf_ror16 rRIP, R16;

        vmovdqa .Liv+(0 * 8) rRIP, ROW3;
        vmovdqa .Liv+(4 * 8) rRIP, ROW4;

        vmovdqu (STATE_H + 0 * 8)(RSTATE), ROW1;
        vmovdqu (STATE_H + 4 * 8)(RSTATE), ROW2;

        vpxor (STATE_T)(RSTATE), ROW4, ROW4;

        LOAD_MSG(0, MA1, MA2, MA3, MA4);
        LOAD_MSG(1, MB1, MB2, MB3, MB4);

.align 16
.Loop:
        ROUND(0, MA1, MA2, MA3, MA4);
                                      LOAD_MSG(2, MA1, MA2, MA3, MA4);
        ROUND(1, MB1, MB2, MB3, MB4);
                                      LOAD_MSG(3, MB1, MB2, MB3, MB4);
        ROUND(2, MA1, MA2, MA3, MA4);
                                      LOAD_MSG(4, MA1, MA2, MA3, MA4);
        ROUND(3, MB1, MB2, MB3, MB4);
                                      LOAD_MSG(5, MB1, MB2, MB3, MB4);
        ROUND(4, MA1, MA2, MA3, MA4);
                                      LOAD_MSG(6, MA1, MA2, MA3, MA4);
        ROUND(5, MB1, MB2, MB3, MB4);
                                      LOAD_MSG(7, MB1, MB2, MB3, MB4);
        ROUND(6, MA1, MA2, MA3, MA4);
                                      LOAD_MSG(8, MA1, MA2, MA3, MA4);
        ROUND(7, MB1, MB2, MB3, MB4);
                                      LOAD_MSG(9, MB1, MB2, MB3, MB4);
        ROUND(8, MA1, MA2, MA3, MA4);
                                      LOAD_MSG(10, MA1, MA2, MA3, MA4);
        ROUND(9, MB1, MB2, MB3, MB4);
                                      LOAD_MSG(11, MB1, MB2, MB3, MB4);
        sub $1, RNBLKS;
        jz .Loop_end;

        lea 128(RINBLKS), RINBLKS;
        addq $128, (STATE_T + 0)(RSTATE);
        adcq $0, (STATE_T + 8)(RSTATE);

        ROUND(10, MA1, MA2, MA3, MA4);
                                      LOAD_MSG(0, MA1, MA2, MA3, MA4);
        ROUND(11, MB1, MB2, MB3, MB4);
                                      LOAD_MSG(1, MB1, MB2, MB3, MB4);

        vpternlogq $0x96, (STATE_H + 0 * 8)(RSTATE), ROW3, ROW1;
        vpternlogq $0x96, (STATE_H + 4 * 8)(RSTATE), ROW4, ROW2;

        vmovdqa .Liv+(0 * 8) rRIP, ROW3;
        vmovdqa .Liv+(4 * 8) rRIP, ROW4;

        vmovdqu ROW1, (STATE_H + 0 * 8)(RSTATE);
        vmovdqu ROW2, (STATE_H + 4 * 8)(RSTATE);

        vpxor (STATE_T)(RSTATE), ROW4, ROW4;

        jmp .Loop;

.align 16
.Loop_end:
        ROUND(10, MA1, MA2, MA3, MA4);
        ROUND(11, MB1, MB2, MB3, MB4);

        vpternlogq $0x96, (STATE_H + 0 * 8)(RSTATE), ROW3, ROW1;
        vpternlogq $0x96, (STATE_H + 4 * 8)(RSTATE), ROW4, ROW2;

        vmovdqu ROW1, (STATE_H + 0 * 8)(RSTATE);
        vmovdqu ROW2, (STATE_H + 4 * 8)(RSTATE);

        xorl %eax, %eax;
        kxord %k1, %k1, %k1;
        kxord %k2, %k2, %k2;
        kxord %k3, %k3, %k3;

        vzeroall;
        ret_spec_stop;
        CFI_ENDPROC();
ELF(.size _gcry_blake2b_transform_amd64_avx512,
    .-_gcry_blake2b_transform_amd64_avx512;)

#endif /*defined(HAVE_COMPATIBLE_GCC_AMD64_PLATFORM_AS)*/
#endif /*__x86_64*/
