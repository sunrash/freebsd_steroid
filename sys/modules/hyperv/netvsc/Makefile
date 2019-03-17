# $FreeBSD: releng/12.0/sys/modules/hyperv/netvsc/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH:  ${SRCTOP}/sys/dev/hyperv/netvsc \
	${SRCTOP}/sys/dev/hyperv/vmbus

KMOD=	hv_netvsc
SRCS=	hn_nvs.c hn_rndis.c if_hn.c
SRCS+=	bus_if.h device_if.h vmbus_if.h
SRCS+=	opt_hn.h opt_inet.h opt_inet6.h opt_rss.h

CFLAGS+= -I${SRCTOP}/sys/dev/hyperv/netvsc

.include <bsd.kmod.mk>
