# $FreeBSD: releng/12.0/usr.sbin/bsnmpd/tools/Makefile.inc 325178 2017-10-31 00:03:25Z bdrewery $
# Author: Shteryana Shopova <syrinx@FreeBSD.org>

BINDIR?= /usr/bin
PACKAGE=	bsnmp

CFLAGS+= -I. -I${.CURDIR}

WARNS?=		6
