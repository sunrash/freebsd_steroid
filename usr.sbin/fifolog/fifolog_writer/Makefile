# $FreeBSD: releng/12.0/usr.sbin/fifolog/fifolog_writer/Makefile 314479 2017-03-01 05:21:21Z ngie $

PROG=	fifolog_writer

CFLAGS+= -I${.CURDIR:H}/lib

MAN=

LIBADD=	fifolog

regress:
	date | ./${PROG} -z 0 /tmp/fifolog.0
	lptest 65 | ./${PROG} -z 9 /tmp/fifolog.1

.include <bsd.prog.mk>
