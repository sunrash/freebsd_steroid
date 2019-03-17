# $FreeBSD: releng/12.0/lib/libc/aarch64/Makefile.inc 314557 2017-03-02 17:07:28Z brooks $
#
# Machine dependent definitions for the arm 64-bit architecture.
#

# Long double is quad precision
GDTOASRCS+=strtorQ.c
SRCS+=machdep_ldisQ.c
SYM_MAPS+=${LIBC_SRCTOP}/aarch64/Symbol.map
