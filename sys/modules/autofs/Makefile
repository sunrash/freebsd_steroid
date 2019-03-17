# $FreeBSD: releng/12.0/sys/modules/autofs/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH: ${SRCTOP}/sys/fs/autofs

KMOD=	autofs
SRCS=	vnode_if.h \
	autofs.c \
	autofs_vnops.c \
	autofs_vfsops.c

.include <bsd.kmod.mk>
