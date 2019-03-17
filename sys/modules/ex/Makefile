# $FreeBSD: releng/12.0/sys/modules/ex/Makefile 314651 2017-03-04 10:10:17Z ngie $
#

.PATH:	${SRCTOP}/sys/dev/ex

KMOD=	if_ex
SRCS=	if_ex.c \
	if_ex_isa.c isa_if.h \
	if_ex_pccard.c card_if.h \
	bus_if.h device_if.h pccarddevs.h

.include <bsd.kmod.mk>
