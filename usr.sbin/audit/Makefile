#
# $FreeBSD: releng/12.0/usr.sbin/audit/Makefile 314659 2017-03-04 11:38:03Z ngie $
#

OPENBSMDIR=${SRCTOP}/contrib/openbsm
.PATH: ${OPENBSMDIR}/bin/audit

CFLAGS+=	-I${OPENBSMDIR}

PROG=	audit
MAN=	audit.8

LIBADD=	bsm

WARNS?=	5

.include <bsd.prog.mk>
