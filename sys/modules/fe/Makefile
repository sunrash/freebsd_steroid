# $FreeBSD: releng/12.0/sys/modules/fe/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH: ${SRCTOP}/sys/dev/fe

KMOD=	if_fe
SRCS=	if_fe.c if_fe_isa.c if_fe_pccard.c

SRCS+=	bus_if.h card_if.h device_if.h isa_if.h pccarddevs.h

.include <bsd.kmod.mk>
