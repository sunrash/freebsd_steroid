# $FreeBSD: releng/12.0/sbin/fdisk/Makefile 314656 2017-03-04 11:33:01Z ngie $

PACKAGE=runtime
PROG=	fdisk
SRCS=	fdisk.c geom_mbr_enc.c
WARNS?=	4
MAN=	fdisk.8

.PATH:	${SRCTOP}/sys/geom

LIBADD=	geom

.include <bsd.prog.mk>

test:	${PROG}
	sh ${.CURDIR}/runtest.sh
