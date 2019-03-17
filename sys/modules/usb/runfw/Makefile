# $FreeBSD: releng/12.0/sys/modules/usb/runfw/Makefile 314651 2017-03-04 10:10:17Z ngie $

KMOD=	runfw
FIRMWS=	run.fw:runfw:1

CLEANFILES=	run.fw

run.fw: ${SRCTOP}/sys/contrib/dev/run/rt2870.fw.uu
	uudecode -p $? > ${.TARGET}

.include <bsd.kmod.mk>
