#	@(#)Makefile	8.1 (Berkeley) 6/5/93
# $FreeBSD: releng/12.0/sbin/restore/Makefile 314656 2017-03-04 11:33:01Z ngie $

.PATH: ${.CURDIR:H}/dump

PACKAGE=runtime
PROG=	restore
LINKS=	${BINDIR}/restore ${BINDIR}/rrestore
MAN=	restore.8
MLINKS=	restore.8 rrestore.8
SRCS=	main.c interactive.c restore.c dirs.c symtab.c tape.c utilities.c \
	dumprmt.c
WARNS?=	2
CFLAGS+= -DRRESTORE -D_ACL_PRIVATE

.include <bsd.prog.mk>
