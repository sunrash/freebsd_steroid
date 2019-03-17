# $FreeBSD: releng/12.0/usr.sbin/uathload/Makefile 314451 2017-03-01 03:59:18Z ngie $

PROG=	uathload
MAN=	uathload.8

SRCS=	uathload.c
FILES=	ar5523.bin
FILESDIR=	${SHAREDIR}/firmware
FILESMODE=	444

CLEANFILES=	ar5523.bin

ar5523.bin: ${SRCTOP}/sys/contrib/dev/uath/ar5523.bin.uu
	uudecode -p ${.ALLSRC} > ${.TARGET}

.include <bsd.prog.mk>
