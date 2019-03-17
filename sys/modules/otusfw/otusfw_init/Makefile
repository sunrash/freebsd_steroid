# $FreeBSD: releng/12.0/sys/modules/otusfw/otusfw_init/Makefile 314651 2017-03-04 10:10:17Z ngie $

KMOD=	otusfw_init
FIRMWS=	otusfw_init:otusfw_init:1

CLEANFILES=	otus_init

otusfw_init: ${SRCTOP}/sys/contrib/dev/otus/otus-init
	cp ${.ALLSRC} ${.TARGET}

.include <bsd.kmod.mk>
