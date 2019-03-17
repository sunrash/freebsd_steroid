# $FreeBSD: releng/12.0/stand/efi/loader/arch/i386/Makefile.inc 325093 2017-10-29 05:26:59Z imp $

SRCS+=	start.S \
	efimd.c \
	elf32_freebsd.c \
	exec.c

.PATH:	${BOOTSRC}/i386/libi386
SRCS+=	nullconsole.c \
	comconsole.c \
	spinconsole.c

CFLAGS+=	-fPIC -DTERM_EMU
LDFLAGS+=	-Wl,-znocombreloc
