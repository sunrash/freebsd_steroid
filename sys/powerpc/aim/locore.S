/* $FreeBSD: releng/12.0/sys/powerpc/aim/locore.S 304051 2016-08-13 18:46:49Z jhibbits $ */

#ifdef __powerpc64__
#include <powerpc/aim/locore64.S>
#else
#include <powerpc/aim/locore32.S>
#endif

/*
 * XXX: This should be moved to a shared AIM/booke asm file, if one ever is
 * created.
 */
ENTRY(get_spr)
	mfspr	%r3, 0
	blr
