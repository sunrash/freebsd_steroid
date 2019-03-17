# $FreeBSD: releng/12.0/usr.bin/smbutil/Makefile 315170 2017-03-12 18:58:44Z imp $

PROG=	smbutil
SRCS=	smbutil.c dumptree.c login.c lookup.c view.c print.c

LIBADD=	smb

CONTRIBDIR=	${SRCTOP}/contrib/smbfs
CFLAGS+=	-I${CONTRIBDIR}/include

WARNS?=	0

.PATH:	${CONTRIBDIR}/smbutil

.include <bsd.prog.mk>
