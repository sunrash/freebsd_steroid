# $FreeBSD: releng/12.0/lib/libc/sparc64/sys/Makefile.inc 334626 2018-06-04 19:35:15Z markj $

SRCS+=	__sparc_sigtramp_setup.c \
	__sparc_utrap.c \
	__sparc_utrap_align.c \
	__sparc_utrap_emul.c \
	__sparc_utrap_fp_disabled.S \
	__sparc_utrap_gen.S \
	__sparc_utrap_install.c \
	__sparc_utrap_setup.c \
	sigcode.S

CFLAGS+= -I${LIBC_SRCTOP}/sparc64/fpu

MDASM+=	cerror.S sigaction1.S
