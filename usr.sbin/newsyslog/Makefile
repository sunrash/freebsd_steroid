# $FreeBSD: releng/12.0/usr.sbin/newsyslog/Makefile 337686 2018-08-12 13:24:53Z brd $

.include <src.opts.mk>

CONFS=	newsyslog.conf
PROG=	newsyslog
MAN=	newsyslog.8 newsyslog.conf.5
SRCS=	newsyslog.c ptimes.c
LIBADD=	sbuf

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests
SUBDIR+=	newsyslog.conf.d

.include <bsd.prog.mk>
