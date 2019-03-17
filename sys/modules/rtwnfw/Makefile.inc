# $FreeBSD: releng/12.0/sys/modules/rtwnfw/Makefile.inc 314651 2017-03-04 10:10:17Z ngie $
#
# Common rules for building firmware.  Note this gets auto-included
# by the subdir Makefile's as a consequence of included bsd.kmod.mk.

_FIRM=	${IMG}.fw

CLEANFILES+=	${_FIRM}

FIRMWS=	${_FIRM}:${KMOD}:111

# FIRMWARE_LICENSE=	realtek

${_FIRM}: ${SRCTOP}/sys/contrib/dev/rtwn/${_FIRM}.uu
	uudecode -p $? > ${.TARGET}
