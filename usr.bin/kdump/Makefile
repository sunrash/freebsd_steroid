#	@(#)Makefile	8.1 (Berkeley) 6/6/93
# $FreeBSD: releng/12.0/usr.bin/kdump/Makefile 323866 2017-09-21 14:41:41Z oshogbo $

.include <src.opts.mk>

.PATH: ${SRCTOP}/usr.bin/ktrace

PROG=		kdump
SRCS=		kdump.c subr.c
CFLAGS+=	-I${SRCTOP}/usr.bin/ktrace

LIBADD=		sysdecode
.if ${MK_CASPER} != "no"
LIBADD+=	casper
LIBADD+=	cap_grp
LIBADD+=	cap_pwd
CFLAGS+=-DWITH_CASPER
.endif

#NO_WERROR?=	YES

.include <bsd.prog.mk>
