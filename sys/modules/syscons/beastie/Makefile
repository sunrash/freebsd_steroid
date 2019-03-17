# $FreeBSD: releng/12.0/sys/modules/syscons/beastie/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH:	${SRCTOP}/sys/dev/syscons/logo

KMOD=	beastie_saver
SRCS=	beastie.c logo_saver.c

CFLAGS+=-DBEASTIE_LOGO

.include <bsd.kmod.mk>
