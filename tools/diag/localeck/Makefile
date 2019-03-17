# $FreeBSD: releng/12.0/tools/diag/localeck/Makefile 264400 2014-04-13 05:21:56Z imp $

PROG=	localeck
MAN=
WARNS?=	4

LOCALEDIR?= /usr/share/locale

test: ${PROG}
	sh docheck.sh ${LOCALEDIR}

.include <bsd.prog.mk>
