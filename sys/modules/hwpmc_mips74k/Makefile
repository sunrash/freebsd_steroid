#
# $FreeBSD: releng/12.0/sys/modules/hwpmc_mips74k/Makefile 314651 2017-03-04 10:10:17Z ngie $
#

.PATH: ${SRCTOP}/sys/dev/hwpmc

KMOD=	hwpmc_mips74k

SRCS=	hwpmc_mod.c hwpmc_logging.c hwpmc_soft.c vnode_if.h
SRCS+=	hwpmc_mips.c

SRCS+=	hwpmc_mips74k.c

.include <bsd.kmod.mk>
