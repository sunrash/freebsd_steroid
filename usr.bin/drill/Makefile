# $FreeBSD: releng/12.0/usr.bin/drill/Makefile 315170 2017-03-12 18:58:44Z imp $

# Vendor sources and generated files
LDNSDIR= ${SRCTOP}/contrib/ldns

.PATH: ${LDNSDIR}/drill

PROG=	drill
SRCS=	drill.c drill_util.c error.c root.c work.c \
	chasetrace.c dnssec.c securetrace.c
CFLAGS+= -I${LDNSDIR}
NO_WERROR= true
MAN=	drill.1

LIBADD=	ldns crypto

.include <bsd.prog.mk>
