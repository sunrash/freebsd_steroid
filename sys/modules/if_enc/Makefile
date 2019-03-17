# $FreeBSD: releng/12.0/sys/modules/if_enc/Makefile 314651 2017-03-04 10:10:17Z ngie $

SYSDIR?=${SRCTOP}/sys
.include "${SYSDIR}/conf/kern.opts.mk"

.PATH: ${SYSDIR}/net

KMOD=	if_enc
SRCS=	if_enc.c opt_inet.h opt_inet6.h

.include <bsd.kmod.mk>
