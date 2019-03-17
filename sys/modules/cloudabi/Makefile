# $FreeBSD: releng/12.0/sys/modules/cloudabi/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH: ${SRCTOP}/sys/compat/cloudabi

KMOD=	cloudabi
SRCS=	cloudabi_clock.c cloudabi_errno.c cloudabi_fd.c cloudabi_file.c \
	cloudabi_futex.c cloudabi_mem.c cloudabi_proc.c cloudabi_random.c \
	cloudabi_sock.c cloudabi_thread.c cloudabi_vdso.c vnode_if.h

.include <bsd.kmod.mk>
