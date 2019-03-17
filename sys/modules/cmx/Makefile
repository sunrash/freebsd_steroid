# $FreeBSD: releng/12.0/sys/modules/cmx/Makefile 314651 2017-03-04 10:10:17Z ngie $
#
.PATH:	${SRCTOP}/sys/dev/cmx

KMOD=	cmx
SRCS=	cmx.c cmxvar.h cmxreg.h \
	cmx_pccard.c \
	pccarddevs.h device_if.h bus_if.h card_if.h

.include <bsd.kmod.mk>
