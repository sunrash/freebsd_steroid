#	@(#)Makefile	8.1 (Berkeley) 6/6/93
# $FreeBSD: releng/12.0/usr.bin/tftp/Makefile 315170 2017-03-12 18:58:44Z imp $

.PATH: ${SRCTOP}/libexec/tftpd

PROG=	tftp
SRCS=	main.c tftp-file.c tftp-io.c tftp-options.c tftp-transfer.c
SRCS+=	tftp-utils.c tftp.c
CFLAGS+=-I${SRCTOP}/libexec/tftpd

LIBADD=	edit

.include <bsd.prog.mk>
