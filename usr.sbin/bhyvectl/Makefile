#
# $FreeBSD: releng/12.0/usr.sbin/bhyvectl/Makefile 314659 2017-03-04 11:38:03Z ngie $
#

PROG=	bhyvectl
SRCS=	bhyvectl.c
PACKAGE=	bhyve

MAN=	bhyvectl.8

LIBADD=	vmmapi util

WARNS?=	3

CFLAGS+= -I${SRCTOP}/sys/amd64/vmm

.include <bsd.prog.mk>
