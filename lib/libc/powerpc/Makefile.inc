# $FreeBSD: releng/12.0/lib/libc/powerpc/Makefile.inc 314557 2017-03-02 17:07:28Z brooks $

SRCS+=	trivial-vdso_tc.c

# Long double is 64-bits
SRCS+=machdep_ldisd.c
SYM_MAPS+=${LIBC_SRCTOP}/powerpc/Symbol.map
