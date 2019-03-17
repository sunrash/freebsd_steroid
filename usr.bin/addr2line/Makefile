# $FreeBSD: releng/12.0/usr.bin/addr2line/Makefile 298401 2016-04-21 12:58:29Z emaste $

.include <src.opts.mk>

ELFTCDIR=	${SRCTOP}/contrib/elftoolchain
ADDR2LINEDIR=	${ELFTCDIR}/addr2line

.PATH: ${ADDR2LINEDIR}

PROG=	addr2line

LIBADD=	elftc dwarf elf

CFLAGS+=-I${ELFTCDIR}/libelftc -I${ELFTCDIR}/common

.include <bsd.prog.mk>
