# $FreeBSD: releng/12.0/usr.sbin/bsnmpd/tools/bsnmptools/Makefile 311174 2017-01-03 22:31:05Z ngie $
# Author: Shteryana Shopova <syrinx@FreeBSD.org>

.include <src.opts.mk>

.PATH: ${.CURDIR}

PROG=	bsnmpget

LIBADD=	bsnmp bsnmptools

CFLAGS+=	-I${.CURDIR:H}/libbsnmptools
LDFLAGS+=	-L${.OBJDIR:H}/libbsnmptools

LINKS=  ${BINDIR}/bsnmpget ${BINDIR}/bsnmpwalk
LINKS+=  ${BINDIR}/bsnmpget ${BINDIR}/bsnmpset

MAN=	bsnmpget.1

MLINKS=		bsnmpget.1 bsnmpwalk.1
MLINKS+=	bsnmpget.1 bsnmpset.1

.include <bsd.prog.mk>
