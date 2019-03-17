#	@(#)Makefile	8.1 (Berkeley) 6/4/93
# $FreeBSD: releng/12.0/libexec/tftpd/Makefile 330696 2018-03-09 15:30:20Z asomers $

.include <src.opts.mk>

PROG=	tftpd
MAN=	tftpd.8
SRCS=	tftp-file.c tftp-io.c tftp-options.c tftp-transfer.c tftp-utils.c
SRCS+=	tftpd.c
WFORMAT=0

.if ${MK_TCP_WRAPPERS} != "no"
CFLAGS+=	-DLIBWRAP
LIBADD=	wrap
.endif

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>
