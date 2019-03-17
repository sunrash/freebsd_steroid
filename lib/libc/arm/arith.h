/*
 * MD header for contrib/gdtoa
 *
 * $FreeBSD: releng/12.0/lib/libc/arm/arith.h 255361 2013-09-07 14:04:10Z andrew $
 */

/*
 * NOTE: The definitions in this file must be correct or strtod(3) and
 * floating point formats in printf(3) will break!  The file can be
 * generated by running contrib/gdtoa/arithchk.c on the target
 * architecture.  See contrib/gdtoa/gdtoaimp.h for details.
 */

#if !defined(__ARMEB__) && (defined(__VFP_FP__) || defined(__ARM_EABI__))
#define IEEE_8087
#define Arith_Kind_ASL 1
#define Sudden_Underflow
#else
#define IEEE_MC68k
#define Arith_Kind_ASL 2
#endif
