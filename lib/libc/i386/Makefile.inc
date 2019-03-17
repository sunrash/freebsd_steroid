# $FreeBSD: releng/12.0/lib/libc/i386/Makefile.inc 326908 2017-12-16 15:17:54Z emaste $

# Long double is 80 bits
GDTOASRCS+=strtorx.c
SRCS+=machdep_ldisx.c
SYM_MAPS+=${LIBC_SRCTOP}/i386/Symbol.map
