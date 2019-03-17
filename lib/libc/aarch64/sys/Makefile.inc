# $FreeBSD: releng/12.0/lib/libc/aarch64/sys/Makefile.inc 332080 2018-04-05 18:17:46Z brooks $

MIASM:=	${MIASM:Nfreebsd[467]_*}

SRCS+=	__vdso_gettc.c

MDASM=	cerror.S \
	syscall.S \
	vfork.S

# Don't generate default code for these syscalls:
NOASM+=	sbrk.o \
	vfork.o
