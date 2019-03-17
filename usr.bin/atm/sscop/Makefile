# $FreeBSD: releng/12.0/usr.bin/atm/sscop/Makefile 313653 2017-02-11 20:19:04Z ngie $

CONTRIB= ${SRCTOP}/contrib/ngatm/sscop

.PATH:	${CONTRIB}

PROG=	sscop
SRCS=	common.c sscop_main.c
CFLAGS+= -I${CONTRIB} -DUSE_LIBBEGEMOT

LIBADD=	begemot ngatm

.include <bsd.prog.mk>
