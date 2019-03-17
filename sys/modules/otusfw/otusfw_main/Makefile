# $FreeBSD: releng/12.0/sys/modules/otusfw/otusfw_main/Makefile 314651 2017-03-04 10:10:17Z ngie $

KMOD=	otusfw_main
FIRMWS=	otusfw_main:otusfw_main:1

CLEANFILES=	otusfw_main

otusfw_main: ${SRCTOP}/sys/contrib/dev/otus/otus-main
	cp ${.ALLSRC} ${.TARGET}

.include <bsd.kmod.mk>
