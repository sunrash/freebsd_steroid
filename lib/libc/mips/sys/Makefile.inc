# $FreeBSD: releng/12.0/lib/libc/mips/sys/Makefile.inc 334626 2018-06-04 19:35:15Z markj $

SRCS+=	trivial-vdso_tc.c

MDASM=  Ovfork.S cerror.S syscall.S

# Don't generate default code for these syscalls:
NOASM+=	sbrk.o vfork.o
