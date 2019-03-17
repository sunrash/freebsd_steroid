# $FreeBSD: releng/12.0/usr.bin/ipcrm/Makefile 315170 2017-03-12 18:58:44Z imp $

PROG=	ipcrm
SRCS=	ipcrm.c ipc.c
LIBADD=	kvm
CFLAGS+=-I${SRCTOP}/usr.bin/ipcs
.PATH:  ${SRCTOP}/usr.bin/ipcs

WARNS?=	0

.include <bsd.prog.mk>
