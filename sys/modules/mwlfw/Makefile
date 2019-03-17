# $FreeBSD: releng/12.0/sys/modules/mwlfw/Makefile 314651 2017-03-04 10:10:17Z ngie $

KMOD=	mw88W8363fw
FIRMWS=	mw88W8363.fw:mw88W8363fw mwlboot.fw:mwlboot

CLEANFILES+= mw88W8363.fw mwlboot.fw

mw88W8363.fw: ${SRCTOP}/sys/contrib/dev/mwl/mw88W8363.fw.uu
	uudecode -p $? > ${.TARGET}

mwlboot.fw: ${SRCTOP}/sys/contrib/dev/mwl/mwlboot.fw.uu
	uudecode -p $? > ${.TARGET}

.include <bsd.kmod.mk>
