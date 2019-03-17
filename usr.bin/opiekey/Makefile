# $FreeBSD: releng/12.0/usr.bin/opiekey/Makefile 315170 2017-03-12 18:58:44Z imp $
#
OPIE_DIST?=	${SRCTOP}/contrib/opie

PROG=	opiekey

CFLAGS+=-I${SRCTOP}/lib/libopie
CFLAGS+=-I${OPIE_DIST}
CFLAGS+=-DINSECURE_OVERRIDE

WARNS?=	0

LIBADD=	opie

LINKS=	${BINDIR}/opiekey ${BINDIR}/otp-md4
LINKS+=	${BINDIR}/opiekey ${BINDIR}/otp-md5
LINKS+=	${BINDIR}/opiekey ${BINDIR}/otp-sha1

MLINKS=	opiekey.1 otp-md4.1 opiekey.1 otp-md5.1 opiekey.1 otp-sha1.1

.PATH:	${OPIE_DIST}

.include <bsd.prog.mk>
