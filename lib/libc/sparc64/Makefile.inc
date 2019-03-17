# $FreeBSD: releng/12.0/lib/libc/sparc64/Makefile.inc 314557 2017-03-02 17:07:28Z brooks $
#
# Machine dependent definitions for the ultra sparc architecture.
#

.include "fpu/Makefile.inc"

SRCS+=	trivial-vdso_tc.c

# Long double is quad precision
GDTOASRCS+=strtorQ.c
SRCS+=machdep_ldisQ.c
SYM_MAPS+=${LIBC_SRCTOP}/sparc64/Symbol.map
