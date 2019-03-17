# $FreeBSD: releng/12.0/sys/modules/fuse/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH: ${SRCTOP}/sys/fs/fuse

KMOD=	fuse
SRCS=	vnode_if.h \
	fuse_node.c fuse_io.c fuse_device.c fuse_ipc.c fuse_file.c \
	fuse_vfsops.c fuse_vnops.c fuse_internal.c fuse_main.c

.include <bsd.kmod.mk>
