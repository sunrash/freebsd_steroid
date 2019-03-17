# $FreeBSD: releng/12.0/usr.sbin/iscsid/Makefile 314659 2017-03-04 11:38:03Z ngie $

PACKAGE=	iscsi
PROG=		iscsid
SRCS=		chap.c discovery.c iscsid.c keys.c log.c login.c pdu.c
CFLAGS+=	-I${.CURDIR}
CFLAGS+=	-I${SRCTOP}/sys/cam
CFLAGS+=	-I${SRCTOP}/sys/dev/iscsi
CFLAGS+=	-DICL_KERNEL_PROXY
MAN=		iscsid.8

LIBADD=		md util

WARNS=		6

.include <bsd.prog.mk>
