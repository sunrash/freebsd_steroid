# $FreeBSD: releng/12.0/sbin/ldconfig/Makefile 314656 2017-03-04 11:33:01Z ngie $

PACKAGE=runtime
PROG=	ldconfig
SRCS=	elfhints.c ldconfig.c shlib.c support.c
LDDIR?= ${SRCTOP}/libexec/rtld-aout
CFLAGS+=-I${LDDIR} -DFREEBSD_AOUT
MAN=	ldconfig.8

.PATH: ${LDDIR}

.include <bsd.prog.mk>
