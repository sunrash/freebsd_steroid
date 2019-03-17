# $FreeBSD: releng/12.0/stand/efi/loader/arch/arm64/Makefile.inc 325694 2017-11-10 23:54:58Z imp $

HAVE_FDT=yes

SRCS+=	exec.c \
	start.S

.PATH:	${BOOTSRC}/arm64/libarm64
CFLAGS+=-I${BOOTSRC}/arm64/libarm64
SRCS+=	cache.c

CFLAGS+=	-mgeneral-regs-only
