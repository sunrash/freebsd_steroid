# $FreeBSD: releng/12.0/stand/efi/loader/arch/amd64/Makefile.inc 325093 2017-10-29 05:26:59Z imp $

SRCS+=	amd64_tramp.S \
	start.S \
	elf64_freebsd.c \
	trap.c \
	exc.S

.PATH:	${BOOTSRC}/i386/libi386
SRCS+=	nullconsole.c \
	comconsole.c \
	spinconsole.c

CFLAGS+=	-fPIC -DTERM_EMU
LDFLAGS+=	-Wl,-znocombreloc
