# $FreeBSD: releng/12.0/sys/modules/iwmfw/Makefile.inc 314651 2017-03-04 10:10:17Z ngie $
#
# Common rules for building firmware.  Note this gets auto-included
# by the subdir Makefile's as a consequence of included bsd.kmod.mk.

_FIRM=	${IMG}.fw

CLEANFILES+=	${_FIRM}

FIRMWS=	${_FIRM}:${KMOD}

#
# Note that a license ack is not needed for iwn.
#
#FIRMWARE_LICENSE=

${_FIRM}: ${SRCTOP}/sys/contrib/dev/iwm/${_FIRM}.uu
	uudecode -p $? > ${.TARGET}