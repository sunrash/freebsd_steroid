# $FreeBSD: releng/12.0/usr.sbin/tzsetup/Makefile 314463 2017-03-01 04:23:53Z ngie $

.include <src.opts.mk>

PROG=	tzsetup
MAN=	tzsetup.8

CFLAGS+= -I.

.if ${MK_DIALOG} != no
WARNS?=	3
CFLAGS+=	-I${SRCTOP}/contrib/dialog -DHAVE_DIALOG
LIBADD=	dialog ncursesw
.endif

.include <bsd.prog.mk>
