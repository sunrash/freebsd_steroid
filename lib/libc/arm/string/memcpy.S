/*	$NetBSD: memcpy.S,v 1.4 2003/10/14 07:51:45 scw Exp $	*/

#include <machine/asm.h>
__FBSDID("$FreeBSD: releng/12.0/lib/libc/arm/string/memcpy.S 336783 2018-07-27 21:25:01Z imp $");
#if !defined(_ARM_ARCH_5E) || defined(_STANDALONE)
#include "memcpy_arm.S"
#else
#include "memcpy_xscale.S"
#endif
