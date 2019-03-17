# $FreeBSD: releng/12.0/sys/modules/tcp/tcpmd5/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH: ${SRCTOP}/sys/netipsec

KMOD=   tcpmd5
SRCS=   xform_tcp.c opt_inet.h opt_inet6.h opt_ipsec.h

opt_ipsec.h:
	@echo "#define IPSEC_SUPPORT 1" > ${.TARGET}

.include <bsd.kmod.mk>
