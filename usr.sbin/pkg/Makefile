# $FreeBSD: releng/12.0/usr.sbin/pkg/Makefile 336978 2018-07-31 16:42:03Z brd $

CONFS=	FreeBSD.conf
CONFSDIR=	/etc/pkg
CONFSMODE=	644
PROG=	pkg
SRCS=	pkg.c dns_utils.c config.c
MAN=	pkg.7

CFLAGS+=-I${SRCTOP}/contrib/libucl/include
.PATH:	${SRCTOP}/contrib/libucl/include
LIBADD=	archive fetch ucl sbuf crypto ssl

.include <bsd.prog.mk>
