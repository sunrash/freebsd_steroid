#
# $FreeBSD: releng/12.0/usr.sbin/auditreduce/Makefile 314659 2017-03-04 11:38:03Z ngie $
#

OPENBSMDIR=${SRCTOP}/contrib/openbsm
.PATH: ${OPENBSMDIR}/bin/auditreduce

CFLAGS+=	-I${OPENBSMDIR}

PROG=	auditreduce
MAN=	auditreduce.1

LIBADD=	bsm

WARNS?=	3

.include <bsd.prog.mk>
