# $FreeBSD: releng/12.0/sys/modules/mqueue/Makefile 332122 2018-04-06 17:35:35Z brooks $

.PATH: ${SRCTOP}/sys/kern

KMOD=	mqueuefs
SRCS=	uipc_mqueue.c \
	vnode_if.h \
	opt_posix.h opt_capsicum.h

.include <bsd.kmod.mk>
