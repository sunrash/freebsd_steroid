# $FreeBSD: releng/12.0/usr.bin/etdump/Makefile 331949 2018-04-03 21:08:10Z benno $

PROG=	etdump

MAKEFS_SRC=	${SRCTOP}/usr.sbin/makefs

CFLAGS+=	-I${SRCTOP}/sys/fs/cd9660 -I${MAKEFS_SRC} \
		-I${MAKEFS_SRC}/cd9660

.PATH:	${MAKEFS_SRC}/cd9660

SRCS=		etdump.c output_shell.c output_text.c cd9660_conversion.c

.include <bsd.prog.mk>
