# $FreeBSD: releng/12.0/lib/libc/amd64/Makefile.inc 314557 2017-03-02 17:07:28Z brooks $
#
# Machine dependent definitions for the amd64 architecture.
#

# Long double is 80 bits
GDTOASRCS+=strtorx.c
SRCS+=machdep_ldisx.c
SYM_MAPS+=${LIBC_SRCTOP}/amd64/Symbol.map
