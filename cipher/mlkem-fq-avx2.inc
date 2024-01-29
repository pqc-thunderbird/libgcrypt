/* mlkem-fq-avx2.inc
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

.macro red16 r,rs=0,x=12
vpmulhw         %ymm1,%ymm\r,%ymm\x
.if \rs
vpmulhrsw	%ymm\rs,%ymm\x,%ymm\x
.else
vpsraw          $10,%ymm\x,%ymm\x
.endif
vpmullw         %ymm0,%ymm\x,%ymm\x
vpsubw          %ymm\x,%ymm\r,%ymm\r
.endm

.macro csubq r,x=12
vpsubw		%ymm0,%ymm\r,%ymm\r
vpsraw		$15,%ymm\r,%ymm\x
vpand		%ymm0,%ymm\x,%ymm\x
vpaddw		%ymm\x,%ymm\r,%ymm\r
.endm

.macro caddq r,x=12
vpsraw		$15,%ymm\r,%ymm\x
vpand		%ymm0,%ymm\x,%ymm\x
vpaddw		%ymm\x,%ymm\r,%ymm\r
.endm

.macro fqmulprecomp al,ah,b,x=12
vpmullw		%ymm\al,%ymm\b,%ymm\x
vpmulhw		%ymm\ah,%ymm\b,%ymm\b
vpmulhw		%ymm0,%ymm\x,%ymm\x
vpsubw		%ymm\x,%ymm\b,%ymm\b
.endm
