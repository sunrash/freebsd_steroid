# $FreeBSD: releng/12.0/sys/modules/msdosfs/Makefile 319735 2017-06-09 12:06:22Z kib $

.PATH: ${SRCTOP}/sys/fs/msdosfs

KMOD=	msdosfs
SRCS=	vnode_if.h \
	msdosfs_conv.c msdosfs_denode.c msdosfs_fat.c \
	msdosfs_lookup.c msdosfs_vfsops.c msdosfs_vnops.c
EXPORT_SYMS=	msdosfs_iconv

.include <bsd.kmod.mk>
