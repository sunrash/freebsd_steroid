# $FreeBSD: releng/12.0/lib/libc/riscv/sys/Makefile.inc 334626 2018-06-04 19:35:15Z markj $

SRCS+=	trivial-vdso_tc.c

MDASM=	cerror.S \
	syscall.S \
	vfork.S

# Don't generate default code for these syscalls:
NOASM+=	sbrk.o vfork.o
