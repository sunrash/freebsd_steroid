# $FreeBSD: releng/12.0/sys/modules/wpifw/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH: ${SRCTOP}/sys/contrib/dev/wpi

KMOD=	wpifw
FIRMWS=	iwlwifi-3945-15.32.2.9.fw:wpifw:153229

CLEANFILES=	iwlwifi-3945-15.32.2.9.fw

iwlwifi-3945-15.32.2.9.fw: iwlwifi-3945-15.32.2.9.fw.uu
	uudecode -p ${.ALLSRC} > ${.TARGET}

.include <bsd.kmod.mk>
